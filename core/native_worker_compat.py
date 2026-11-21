"""Runtime-entrypoint compatibility for self-relaunching worker helpers.

Obfuscated payloads may execute inside a temporary native extension module.
In that case ``__file__`` can point at a transient ``.so`` which the outer
launcher deletes after loading.  A worker command built from that path cannot
re-enter the application.  Cython ``--embed`` has the inverse shape: its
``__file__`` is synthetic (often ``built-in``), while ``sys.argv[0]`` names the
native executable.

The pass resolves the real process entrypoint from ``sys.argv[0]`` and uses
that path for every ``Path(__file__)`` reference.  Worker relaunch commands
then select either ``[sys.executable, script.py, ...]`` or
``[native_executable, ...]`` according to the resolved entrypoint suffix.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


_HELPER_NAME = "_vh_runtime_entry_path"
_PYTHON_SUFFIXES = (".py", ".pyw", ".pyc", ".pyo")


@dataclass
class NativeWorkerCompatReport:
    functions_scanned: int = 0
    functions_patched: int = 0
    commands_patched: int = 0
    path_references_patched: int = 0
    skipped_by_reason: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped_by_reason[reason] = self.skipped_by_reason.get(reason, 0) + 1


def _path_alias(tree: ast.Module) -> str | None:
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "pathlib":
            for alias in node.names:
                if alias.name == "Path":
                    return alias.asname or "Path"
    return None


def _is_sys_executable(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "executable"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _target_names(node: ast.stmt) -> set[str]:
    names: set[str] = set()
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            for child in ast.walk(target):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    names.add(child.id)
    return names


def _has_dunder_file(node: ast.AST) -> bool:
    return any(isinstance(item, ast.Name) and item.id == "__file__" for item in ast.walk(node))


def _is_path_derivation(value: ast.AST) -> bool:
    """Recognize Path(__file__) and wrappers such as str(Path(__file__).resolve())."""
    if isinstance(value, ast.Call) and len(value.args) == 1:
        return _is_path_derivation(value.args[0])
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        if value.func.attr == "resolve" and isinstance(value.func.value, ast.Call):
            base = value.func.value
            return (
                isinstance(base.func, ast.Name)
                and len(base.args) == 1
                and isinstance(base.args[0], ast.Name)
                and base.args[0].id == "__file__"
            )
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in {"Path"}
        and len(value.args) == 1
        and isinstance(value.args[0], ast.Name)
        and value.args[0].id == "__file__"
    ) or _has_dunder_file(value)


def _script_path_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and _is_path_derivation(node.value):
            names.update(_target_names(node))
    return names


class _FileReferenceRewriter(ast.NodeTransformer):
    def __init__(self, path_constructor: str, report: NativeWorkerCompatReport) -> None:
        self.path_constructor = path_constructor
        self.report = report

    def visit_Call(self, node: ast.Call):
        node = self.generic_visit(node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == self.path_constructor
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "__file__"
        ):
            node.args[0] = ast.Call(
                func=ast.Name(id=_HELPER_NAME, ctx=ast.Load()),
                args=[],
                keywords=[],
            )
            self.report.path_references_patched += 1
        return node


def _make_worker_command_value(original: ast.BinOp, script_name: str) -> ast.expr:
    """Choose Python-script invocation or direct native-executable re-entry."""
    # Construct str(script_path).lower().endswith(...).
    lower_path = ast.Call(
        func=ast.Attribute(
            value=ast.Call(
                func=ast.Name(id="str", ctx=ast.Load()),
                args=[ast.Name(id=script_name, ctx=ast.Load())],
                keywords=[],
            ),
            attr="lower",
            ctx=ast.Load(),
        ),
        args=[],
        keywords=[],
    )
    is_python_script = ast.Call(
        func=ast.Attribute(value=lower_path, attr="endswith", ctx=ast.Load()),
        args=[
            ast.Tuple(
                elts=[ast.Constant(value=item) for item in _PYTHON_SUFFIXES],
                ctx=ast.Load(),
            )
        ],
        keywords=[],
    )
    python_command = ast.List(
        elts=[
            ast.Attribute(value=ast.Name(id="sys", ctx=ast.Load()), attr="executable", ctx=ast.Load()),
            ast.Name(id=script_name, ctx=ast.Load()),
        ],
        ctx=ast.Load(),
    )
    native_command = ast.List(
        elts=[ast.Name(id=script_name, ctx=ast.Load())],
        ctx=ast.Load(),
    )
    selected_command = ast.IfExp(
        test=is_python_script,
        body=python_command,
        orelse=native_command,
    )
    return ast.copy_location(
        ast.BinOp(left=selected_command, op=ast.Add(), right=original.right),
        original,
    )


class _WorkerCommandPatcher(ast.NodeTransformer):
    def __init__(self, report: NativeWorkerCompatReport) -> None:
        self.report = report

    def _patch_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        self.report.functions_scanned += 1
        script_names = _script_path_names(node)
        if not script_names:
            return node
        changed = False

        class CommandVisitor(ast.NodeTransformer):
            def visit_Assign(inner_self, assignment: ast.Assign):
                nonlocal changed
                assignment = inner_self.generic_visit(assignment)
                value = assignment.value
                if not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Add):
                    return assignment
                left = value.left
                if not (
                    isinstance(left, ast.List)
                    and len(left.elts) == 2
                    and _is_sys_executable(left.elts[0])
                    and isinstance(left.elts[1], ast.Name)
                    and left.elts[1].id in script_names
                ):
                    return assignment
                assignment.value = _make_worker_command_value(value, left.elts[1].id)
                changed = True
                self.report.commands_patched += 1
                return assignment

        visitor = CommandVisitor()
        node.body = [visitor.visit(statement) for statement in node.body]
        if changed:
            self.report.functions_patched += 1
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        node = self._patch_function(node)
        node.body = [self.visit(item) for item in node.body]
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        node = self._patch_function(node)
        node.body = [self.visit(item) for item in node.body]
        return node


def _runtime_entry_helper() -> ast.FunctionDef:
    helper_source = '''\
def _vh_runtime_entry_path():
    import pathlib as _vh_pathlib
    import sys as _vh_sys
    _vh_argv = getattr(_vh_sys, "argv", None) or ()
    _vh_candidate_text = _vh_argv[0] if _vh_argv else ""
    if _vh_candidate_text and _vh_candidate_text not in ("-c", "-m"):
        try:
            _vh_candidate = _vh_pathlib.Path(_vh_candidate_text).expanduser()
            if _vh_candidate.is_file():
                return _vh_candidate.resolve()
        except (OSError, RuntimeError, TypeError, ValueError):
            pass
    return _vh_pathlib.Path(__file__).resolve()
'''
    return ast.parse(helper_source).body[0]


def _has_helper(tree: ast.Module) -> bool:
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == _HELPER_NAME
        for node in tree.body
    )


def _insert_helper_after_docstring(tree: ast.Module) -> None:
    index = 1 if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ) else 0
    tree.body.insert(index, _runtime_entry_helper())


def patch_native_worker_reentry(source: str) -> tuple[str, NativeWorkerCompatReport]:
    """Resolve payload file references through sys.argv[0] for all output modes.

    Despite the historical function name, this now supports normal scripts,
    payloads loaded by a temporary native extension, and Cython --embed builds.
    """
    report = NativeWorkerCompatReport()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        report.skip("parse-failed")
        return source, report

    path_constructor = _path_alias(tree)
    if not path_constructor:
        report.skip("pathlib-Path-import-not-found")
        return source, report

    # Collect command candidates before changing Path(__file__) expressions.
    command_patched = _WorkerCommandPatcher(report).visit(tree)
    rewritten = _FileReferenceRewriter(path_constructor, report).visit(command_patched)

    if report.path_references_patched and not _has_helper(rewritten):
        _insert_helper_after_docstring(rewritten)

    if report.commands_patched == 0 and report.path_references_patched == 0:
        report.skip("no-supported-worker-entrypoint-pattern")
        return source, report

    ast.fix_missing_locations(rewritten)
    try:
        transformed = ast.unparse(rewritten) + "\n"
        compile(transformed, "<runtime-worker-entrypoint-compat>", "exec")
    except (SyntaxError, ValueError, TypeError):
        report.skip("transformed-source-invalid")
        return source, NativeWorkerCompatReport(
            functions_scanned=report.functions_scanned,
            skipped_by_reason=report.skipped_by_reason,
        )
    return transformed, report


# Explicit alias for clearer use in new call sites while preserving existing API.
patch_runtime_worker_entrypoint = patch_native_worker_reentry
