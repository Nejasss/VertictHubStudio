"""Forward the per-build launcher gate into privileged worker subprocesses.

The anti-debug launcher gate deliberately removes its environment variable
from the main process after verifying it, while caching the token on a custom
attribute of the imported ``sys`` module. Touch Engine workers are new
processes, so the cached token must be copied into only those child processes.

This build-time AST patch does two things:

* adds the cached token to the explicit export map used by ``su -c`` /
  Shizuku shell commands; and
* passes a copied environment to the local ``subprocess.run`` / ``Popen``
  calls that launch ``--touch-scan`` and ``--touch-worker``. This covers the
  direct-root path where no shell export map is built.

The token value is never embedded in source or emitted in reports.
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field


@dataclass
class WorkerGateForwardingReport:
    functions_scanned: int = 0
    functions_patched: int = 0
    callsites_patched: int = 0
    gate_configured: bool = False
    skipped_by_reason: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped_by_reason[reason] = self.skipped_by_reason.get(reason, 0) + 1


def _is_name(node: ast.AST, value: str) -> bool:
    return isinstance(node, ast.Name) and node.id == value


def _is_command_subprocess_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not (
        isinstance(func, ast.Attribute)
        and _is_name(func.value, "subprocess")
        and func.attr in {"run", "Popen"}
    ):
        return False
    return bool(node.args) and _is_name(node.args[0], "command_parts")


def patch_worker_gate_environment(
    source: str,
    gate_env_name: str | None,
    gate_token_cache_var: str | None,
) -> tuple[str, WorkerGateForwardingReport]:
    """Forward the cached gate token to Root/Shizuku child workers.

    ``gate_token_cache_var`` is the exact custom ``sys`` module attribute
    written by ``antidebug.get_antidebug_source`` before the gate environment
    entry is deleted from the parent process. The generated environment helper
    therefore works after the parent's ``os.environ`` has been scrubbed.
    """
    report = WorkerGateForwardingReport(gate_configured=bool(gate_env_name))
    if not gate_env_name or not gate_token_cache_var:
        report.skip("launcher-gate-disabled-or-cache-attribute-missing")
        return source, report
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", gate_env_name):
        report.skip("invalid-gate-environment-name")
        return source, report

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        report.skip("parse-failed")
        return source, report

    root_helper = next(
        (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_root_python_command"
        ),
        None,
    )
    if root_helper is None:
        report.skip("root-worker-command-not-found")
        return source, report
    report.functions_scanned = 1

    suffix = hashlib.sha256(
        (gate_env_name + "\0" + gate_token_cache_var).encode("utf-8")
    ).hexdigest()[:10]
    env_helper_name = f"_vh_worker_child_env_{suffix}"

    module_helper = next(
        (
            node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == env_helper_name
        ),
        None,
    )

    # Locate the export-map assignment and prefix serialization anchor.
    prefix_index = None
    has_exports_assignment = False
    for index, statement in enumerate(root_helper.body):
        for child in ast.walk(statement):
            if (
                isinstance(child, ast.Name)
                and child.id == "exports"
                and isinstance(child.ctx, ast.Store)
            ):
                has_exports_assignment = True
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(_is_name(target, "prefix") for target in targets):
                prefix_index = index
                break

    # A Cython/native or direct-root path may not need a shell export map.
    # Still require the helper function so run/Popen can receive env=.
    if prefix_index is not None and has_exports_assignment:
        already_forwarded = any(
            isinstance(node, ast.Subscript)
            and _is_name(node.value, "exports")
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == gate_env_name
            for node in ast.walk(root_helper)
        )
        if not already_forwarded:
            token_name = f"_vh_gate_token_{suffix}"
            injected = ast.parse(
                f"""\
{token_name} = getattr(sys, {gate_token_cache_var!r}, None) or os.environ.get({gate_env_name!r}, "")
if {token_name}:
    exports[{gate_env_name!r}] = {token_name}
"""
            ).body
            root_helper.body[prefix_index:prefix_index] = injected
    elif prefix_index is None and has_exports_assignment:
        report.skip("exports-prefix-anchor-not-found")

    # Build a per-child environment. The gate token lives in sys' private
    # cache after startup, so copy it into this child mapping without restoring
    # it to the parent process environment.
    if module_helper is None:
        env_helper = ast.parse(
            f"""\
def {env_helper_name}():
    _vh_env_{suffix} = os.environ.copy()
    _vh_token_{suffix} = getattr(sys, {gate_token_cache_var!r}, None) or os.environ.get({gate_env_name!r}, "")
    if _vh_token_{suffix}:
        _vh_env_{suffix}[{gate_env_name!r}] = _vh_token_{suffix}
    return _vh_env_{suffix}
"""
        ).body[0]
        # Insert immediately before _root_python_command at module level.
        root_module_index = next(
            (
                index for index, node in enumerate(tree.body)
                if node is root_helper
            ),
            None,
        )
        if root_module_index is None:
            report.skip("root-worker-command-not-module-level")
        else:
            tree.body.insert(root_module_index, env_helper)

    # Attach the environment mapping only to subprocess calls that launch the
    # command returned by _root_python_command. No unrelated process receives
    # the launcher gate.
    callsites = 0
    for node in ast.walk(tree):
        if _is_command_subprocess_call(node):
            if not any(keyword.arg == "env" for keyword in node.keywords):
                node.keywords.append(
                    ast.keyword(
                        arg="env",
                        value=ast.Call(
                            func=ast.Name(id=env_helper_name, ctx=ast.Load()),
                            args=[],
                            keywords=[],
                        ),
                    )
                )
                callsites += 1

    report.callsites_patched = callsites
    if module_helper is None or callsites or prefix_index is not None:
        report.functions_patched = 1
    else:
        report.skip("no-worker-subprocess-callsite-found")
        return source, report

    ast.fix_missing_locations(tree)
    try:
        transformed = ast.unparse(tree) + "\n"
        compile(transformed, "<worker-gate-environment-forwarding>", "exec")
    except (SyntaxError, ValueError, TypeError):
        report.skip("transformed-source-invalid")
        return source, report
    return transformed, report
