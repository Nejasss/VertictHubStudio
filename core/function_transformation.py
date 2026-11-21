"""Conservative function-body splitting for source-level obfuscation.

V1 only extracts a short prefix of simple assignments from a top-level,
synchronous, undecorated function into a generated module-level helper.  It
preserves evaluation order and returns every assigned local back to the
original function.  Functions involving recursion, nested scopes, dynamic
introspection, global/nonlocal declarations, generators, async, or ambiguous
local reads are skipped.

This is an opt-in representation change, not a security boundary.  It can
change traceback frames/line numbers and module-global introspection (so the
pass is disabled for a module that uses globals()/vars()/eval()/exec()).
"""
from __future__ import annotations

import ast
import copy
import secrets
from dataclasses import dataclass, field


@dataclass
class FunctionTransformationReport:
    functions_seen: int = 0
    functions_split: int = 0
    helpers_generated: int = 0
    assignments_moved: int = 0
    skipped_by_reason: dict[str, int] = field(default_factory=dict)
    helper_names: list[str] = field(default_factory=list)

    def skip(self, reason: str) -> None:
        self.skipped_by_reason[reason] = self.skipped_by_reason.get(reason, 0) + 1


_REFLECTIVE_CALLS = {"locals", "vars", "globals", "eval", "exec", "dir"}
_REFLECTIVE_ATTRS = {
    "_getframe", "currentframe", "f_locals", "co_varnames", "co_cellvars",
    "co_freevars", "__code__", "__closure__",
}


class _ModuleReflectionScanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.reflective = False
        self.aliases = set(_REFLECTIVE_CALLS)

    def collect_aliases(self, tree: ast.AST) -> None:
        # Collect simple aliases over the whole module before checking calls;
        # aliases may be declared after a function definition but resolved only
        # when that function is later called.
        changed = True
        nodes = list(ast.walk(tree))
        while changed:
            changed = False
            for node in nodes:
                if isinstance(node, ast.ImportFrom):
                    if node.module == "builtins":
                        sensitive = _REFLECTIVE_CALLS
                    elif node.module in {"inspect", "sys"}:
                        sensitive = {"currentframe", "_getframe", "stack", "getouterframes", "getframeinfo"}
                    else:
                        sensitive = set()
                    for alias in node.names:
                        if alias.name in sensitive:
                            bound = alias.asname or alias.name
                            if bound not in self.aliases:
                                self.aliases.add(bound)
                                changed = True
                elif isinstance(node, ast.Assign):
                    source_name = None
                    if isinstance(node.value, ast.Name) and node.value.id in self.aliases:
                        source_name = node.value.id
                    elif isinstance(node.value, ast.Attribute) and (
                        node.value.attr in _REFLECTIVE_CALLS or node.value.attr in _REFLECTIVE_ATTRS
                    ):
                        source_name = node.value.attr
                    if source_name:
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id not in self.aliases:
                                self.aliases.add(target.id)
                                changed = True

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in self.aliases:
            self.reflective = True
        if isinstance(node.func, ast.Attribute) and (
            node.func.attr in _REFLECTIVE_ATTRS or node.func.attr in _REFLECTIVE_CALLS
        ):
            self.reflective = True
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _REFLECTIVE_ATTRS:
            self.reflective = True
        self.generic_visit(node)


class _FunctionFacts(ast.NodeVisitor):
    """Collect scope-local names and reject constructs unsafe for extraction."""
    def __init__(self, function: ast.FunctionDef) -> None:
        self.function = function
        self.local_names = {
            arg.arg for arg in (
                list(function.args.posonlyargs) + list(function.args.args)
                + list(function.args.kwonlyargs)
                + ([function.args.vararg] if function.args.vararg else [])
                + ([function.args.kwarg] if function.args.kwarg else [])
            )
        }
        self.nested_scope = False
        self.global_nonlocal = False
        self.has_yield_or_await = False
        self.reflective = False
        self.recursive = False

    def collect(self) -> None:
        for statement in self.function.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is not self.function:
            self.nested_scope = True
            return
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.nested_scope = True

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.nested_scope = True

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.nested_scope = True

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.local_names.add(node.id)
        elif isinstance(node.ctx, ast.Load) and node.id == self.function.name:
            self.recursive = True

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.local_names.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.local_names.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.local_names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.local_names.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.local_names.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.local_names.add(node.rest)
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.global_nonlocal = True

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.global_nonlocal = True

    def visit_Yield(self, node: ast.Yield) -> None:
        self.has_yield_or_await = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.has_yield_or_await = True

    def visit_Await(self, node: ast.Await) -> None:
        self.has_yield_or_await = True

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in _REFLECTIVE_CALLS:
            self.reflective = True
        if isinstance(node.func, ast.Attribute) and node.func.attr in _REFLECTIVE_ATTRS:
            self.reflective = True
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _REFLECTIVE_ATTRS:
            self.reflective = True
        self.generic_visit(node)


class _NameReadScanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: list[str] = []
        self.unsafe_scope = False

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id not in self.names:
            self.names.append(node.id)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.unsafe_scope = True

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.unsafe_scope = True

    def visit_Yield(self, node: ast.Yield) -> None:
        self.unsafe_scope = True

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.unsafe_scope = True

    def visit_Await(self, node: ast.Await) -> None:
        self.unsafe_scope = True


def _module_uses_reflection(tree: ast.Module) -> bool:
    scanner = _ModuleReflectionScanner()
    scanner.collect_aliases(tree)
    scanner.visit(tree)
    return scanner.reflective


def _fresh_helper_name(used: set[str]) -> str:
    while True:
        name = "_obf_fn_" + secrets.token_hex(4)
        if name not in used:
            used.add(name)
            return name


def _make_helper(
    name: str,
    inputs: list[str],
    moved: list[ast.Assign],
    outputs: list[str],
    location: ast.AST,
) -> ast.FunctionDef:
    args = ast.arguments(
        posonlyargs=[],
        args=[ast.arg(arg=item) for item in inputs],
        vararg=None,
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=None,
        defaults=[],
    )
    if len(outputs) == 1:
        returned: ast.expr = ast.Name(id=outputs[0], ctx=ast.Load())
    else:
        returned = ast.Tuple(
            elts=[ast.Name(id=item, ctx=ast.Load()) for item in outputs],
            ctx=ast.Load(),
        )
    body = [ast.copy_location(copy.deepcopy(stmt), stmt) for stmt in moved]
    body.append(ast.copy_location(ast.Return(value=returned), location))
    helper = ast.FunctionDef(
        name=name,
        args=args,
        body=body,
        decorator_list=[],
        returns=None,
        type_comment=None,
        type_params=[],
    )
    return ast.copy_location(helper, location)


def _eligible_prefix(
    function: ast.FunctionDef,
    local_names: set[str],
    report: FunctionTransformationReport,
) -> tuple[int, list[str], list[str]] | None:
    body = function.body
    start = 1 if (
        body and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ) else 0

    moved: list[ast.Assign] = []
    for statement in body[start:]:
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.type_comment is None
        ):
            break
        scanner = _NameReadScanner()
        scanner.visit(statement.value)
        if scanner.unsafe_scope:
            break
        moved.append(statement)
        if len(moved) >= 4:
            break

    if len(moved) < 2:
        report.skip("no-prefix-of-two-simple-assignments")
        return None

    params = {
        arg.arg for arg in (
            list(function.args.posonlyargs) + list(function.args.args)
            + list(function.args.kwonlyargs)
            + ([function.args.vararg] if function.args.vararg else [])
            + ([function.args.kwarg] if function.args.kwarg else [])
        )
    }
    written: set[str] = set()
    inputs: list[str] = []
    outputs: list[str] = []
    for statement in moved:
        scanner = _NameReadScanner()
        scanner.visit(statement.value)
        if scanner.unsafe_scope:
            report.skip("unsupported-expression-scope")
            return None
        for name in scanner.names:
            if name in local_names and name not in written:
                if name not in params:
                    # Passing an uninitialized local to a helper can change the
                    # order of side effects before UnboundLocalError. Skip it.
                    report.skip("read-before-local-assignment")
                    return None
                if name not in inputs:
                    inputs.append(name)
        target_name = statement.targets[0].id
        written.add(target_name)
        if target_name not in outputs:
            outputs.append(target_name)

    if not outputs:
        report.skip("no-assigned-outputs")
        return None
    return start, inputs, outputs


def transform_functions(source: str) -> tuple[str, FunctionTransformationReport]:
    """Split a safe prefix of simple assignments from eligible top-level defs."""
    report = FunctionTransformationReport()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        report.skip("parse-failed")
        return source, report

    # A helper is a new module global; do not add one if the module exposes or
    # evaluates its namespace dynamically.
    if _module_uses_reflection(tree):
        report.skip("module-reflection")
        return source, report

    used_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    used_names.update(
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    new_body: list[ast.stmt] = []
    changed = False

    for statement in tree.body:
        if not isinstance(statement, ast.FunctionDef):
            new_body.append(statement)
            continue
        report.functions_seen += 1
        reason = None
        if statement.decorator_list:
            reason = "decorated-function"
        else:
            facts = _FunctionFacts(statement)
            facts.collect()
            if facts.nested_scope:
                reason = "nested-scope-or-lambda"
            elif facts.global_nonlocal:
                reason = "global-or-nonlocal"
            elif facts.has_yield_or_await:
                reason = "generator-or-await"
            elif facts.reflective:
                reason = "function-introspection"
            elif facts.recursive:
                reason = "recursive-function"

        if reason:
            report.skip(reason)
            new_body.append(statement)
            continue

        facts = _FunctionFacts(statement)
        facts.collect()
        candidate = _eligible_prefix(statement, facts.local_names, report)
        if candidate is None:
            new_body.append(statement)
            continue

        start, inputs, outputs = candidate
        moved = statement.body[start:start + min(4, len(statement.body) - start)]
        # _eligible_prefix counted only the contiguous assignment prefix. Use
        # that exact count rather than allowing later non-assignment statements.
        moved_count = 0
        for item in statement.body[start:]:
            if not (isinstance(item, ast.Assign) and len(item.targets) == 1
                    and isinstance(item.targets[0], ast.Name) and item.type_comment is None):
                break
            scanner = _NameReadScanner()
            scanner.visit(item.value)
            if scanner.unsafe_scope:
                break
            moved_count += 1
            if moved_count >= 4:
                break
        moved = statement.body[start:start + moved_count]
        helper_name = _fresh_helper_name(used_names)
        helper = _make_helper(helper_name, inputs, moved, outputs, statement)
        if len(outputs) == 1:
            replacement_target: ast.expr = ast.Name(id=outputs[0], ctx=ast.Store())
        else:
            replacement_target = ast.Tuple(
                elts=[ast.Name(id=item, ctx=ast.Store()) for item in outputs],
                ctx=ast.Store(),
            )
        call = ast.Call(
            func=ast.Name(id=helper_name, ctx=ast.Load()),
            args=[ast.Name(id=item, ctx=ast.Load()) for item in inputs],
            keywords=[],
        )
        replacement = ast.copy_location(
            ast.Assign(targets=[replacement_target], value=call), moved[0]
        )
        statement.body = statement.body[:start] + [replacement] + statement.body[start + moved_count:]
        new_body.extend([helper, statement])
        report.functions_split += 1
        report.helpers_generated += 1
        report.assignments_moved += moved_count
        report.helper_names.append(helper_name)
        changed = True

    if not changed:
        return source, report
    tree.body = new_body
    ast.fix_missing_locations(tree)
    try:
        transformed = ast.unparse(tree) + "\n"
        compile(transformed, "<function-transformation>", "exec")
    except (SyntaxError, ValueError, TypeError):
        report.functions_split = 0
        report.helpers_generated = 0
        report.assignments_moved = 0
        report.helper_names.clear()
        report.skip("transformed-source-invalid")
        return source, report
    return transformed, report
