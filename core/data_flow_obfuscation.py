"""Conservative local data-flow reshaping for Python source obfuscation.

V1 supports two semantics-preserving assignment rewrites inside function
scopes only:
  * ``dst = src`` -> ``dst, = (src,)`` (identity-preserving one-item routing)
  * ``dst = expression`` -> ``tmp = expression; dst = tmp`` (single evaluation)

Module/class namespace assignments are left unchanged. Async/generator and
reflective functions are skipped because extra locals can be observed through
frame/local introspection or while suspended. The pass is opt-in and OFF by
default. It does not claim to make runtime values unrecoverable.
"""
from __future__ import annotations

import ast
import secrets
from dataclasses import dataclass, field


@dataclass
class DataFlowObfuscationReport:
    functions_seen: int = 0
    functions_transformed: int = 0
    temporary_routes: int = 0
    tuple_routes: int = 0
    skipped_functions: int = 0
    skipped_assignments: int = 0
    skipped_by_reason: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped_by_reason[reason] = self.skipped_by_reason.get(reason, 0) + 1


_REFLECTIVE_CALLS = {"locals", "vars", "globals", "eval", "exec", "dir"}
_REFLECTIVE_ATTRS = {
    "_getframe", "currentframe", "f_locals", "co_varnames", "co_cellvars",
    "co_freevars", "__code__", "__closure__",
}
_UNSAFE_EXPR_NODES = (ast.NamedExpr, ast.Lambda, ast.Yield, ast.YieldFrom, ast.Await)


class _ScopeSafetyScanner(ast.NodeVisitor):
    def __init__(self, inherited_aliases: set[str] | None = None) -> None:
        self.reflective = False
        self.generator_or_async = False
        self.aliases = set(_REFLECTIVE_CALLS)
        self.aliases.update(inherited_aliases or ())
        self.module_aliases: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            if alias.name.split(".", 1)[0] in {"inspect", "sys", "builtins"}:
                self.module_aliases.add(bound)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "builtins":
            for alias in node.names:
                if alias.name in _REFLECTIVE_CALLS:
                    self.aliases.add(alias.asname or alias.name)
        elif node.module in {"inspect", "sys"}:
            for alias in node.names:
                if alias.name in {"currentframe", "_getframe", "stack", "getouterframes", "getframeinfo"}:
                    self.aliases.add(alias.asname or alias.name)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Name) and node.value.id in self.aliases:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases.add(target.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # The current function body is scanned manually by its caller. Nested
        # function scopes are independent and must not poison their parent.
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in self.aliases:
            self.reflective = True
        if isinstance(node.func, ast.Attribute) and (
            node.func.attr in _REFLECTIVE_ATTRS
            or node.func.attr in _REFLECTIVE_CALLS
            or (isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.module_aliases
                and node.func.attr in {"currentframe", "_getframe", "stack", "getouterframes", "getframeinfo"})
        ):
            self.reflective = True
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _REFLECTIVE_ATTRS or node.attr in _REFLECTIVE_CALLS:
            self.reflective = True
        self.generic_visit(node)

    def visit_Yield(self, node: ast.Yield) -> None:
        self.generator_or_async = True
        self.generic_visit(node)

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.generator_or_async = True
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        self.generator_or_async = True
        self.generic_visit(node)


class _NamePool:
    def __init__(self, tree: ast.AST) -> None:
        self.used = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        }
        self.used.update(
            node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)
        )

    def fresh(self) -> str:
        while True:
            name = "_obf_df_" + secrets.token_hex(4)
            if name not in self.used:
                self.used.add(name)
                return name


class _FunctionBodyTransformer(ast.NodeTransformer):
    def __init__(
        self,
        pool: _NamePool,
        report: DataFlowObfuscationReport,
        inherited_aliases: set[str] | None = None,
    ) -> None:
        self.pool = pool
        self.report = report
        self.inherited_aliases = set(inherited_aliases or ())
        self.changed = 0

    def visit_Assign(self, node: ast.Assign):
        # Only a single local-name target is supported. Destructuring, chained
        # targets, attribute/subscript stores and module/class bodies stay put.
        if (
            len(node.targets) != 1
            or not isinstance(node.targets[0], ast.Name)
            or node.targets[0].id == "_"
            or node.type_comment is not None
        ):
            self.report.skipped_assignments += 1
            return self.generic_visit(node)

        value = node.value
        if isinstance(value, ast.Name):
            target = node.targets[0]
            node.targets = [ast.copy_location(
                ast.Tuple(elts=[target], ctx=ast.Store()), target
            )]
            node.value = ast.copy_location(
                ast.Tuple(elts=[value], ctx=ast.Load()), value
            )
            self.report.tuple_routes += 1
            self.changed += 1
            return node

        if isinstance(value, ast.Constant) or isinstance(value, _UNSAFE_EXPR_NODES):
            self.report.skipped_assignments += 1
            return self.generic_visit(node)
        if any(isinstance(child, _UNSAFE_EXPR_NODES) for child in ast.walk(value)):
            self.report.skipped_assignments += 1
            return self.generic_visit(node)

        temp_name = self.pool.fresh()
        temp_assign = ast.copy_location(
            ast.Assign(
                targets=[ast.Name(id=temp_name, ctx=ast.Store())],
                value=value,
                type_comment=node.type_comment,
            ),
            node,
        )
        node.value = ast.copy_location(ast.Name(id=temp_name, ctx=ast.Load()), value)
        self.report.temporary_routes += 1
        self.changed += 1
        return [temp_assign, node]

    def visit_FunctionDef(self, node: ast.FunctionDef):
        _transform_function(node, self.pool, self.report, self.inherited_aliases)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        _transform_function(node, self.pool, self.report, self.inherited_aliases)
        return node

    def visit_ClassDef(self, node: ast.ClassDef):
        # Only methods/nested functions are eligible; class-body assignments
        # are namespace-visible and must not acquire temporary names.
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _transform_function(item, self.pool, self.report, self.inherited_aliases)
            elif isinstance(item, ast.ClassDef):
                self.visit_ClassDef(item)
        return node


def _function_is_eligible(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    inherited_aliases: set[str] | None = None,
) -> tuple[bool, str]:
    if isinstance(node, ast.AsyncFunctionDef):
        return False, "async-function"
    scanner = _ScopeSafetyScanner(inherited_aliases)
    for statement in node.body:
        scanner.visit(statement)
    if scanner.reflective:
        return False, "dynamic-introspection"
    if scanner.generator_or_async:
        return False, "generator-or-await"
    return True, ""


def _transform_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    pool: _NamePool,
    report: DataFlowObfuscationReport,
    inherited_aliases: set[str] | None = None,
) -> None:
    report.functions_seen += 1
    eligible, reason = _function_is_eligible(node, inherited_aliases)
    if not eligible:
        report.skipped_functions += 1
        report.skip(reason)
        # Still visit nested function scopes: their safety is independent.
        nested = _FunctionBodyTransformer(pool, report, inherited_aliases)
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested.visit(statement)
            elif isinstance(statement, ast.ClassDef):
                nested.visit_ClassDef(statement)
        return

    transformer = _FunctionBodyTransformer(pool, report, inherited_aliases)
    new_body: list[ast.stmt] = []
    for statement in node.body:
        transformed = transformer.visit(statement)
        if isinstance(transformed, list):
            new_body.extend(transformed)
        elif transformed is not None:
            new_body.append(transformed)
    node.body = new_body
    if transformer.changed:
        report.functions_transformed += 1


def _collect_module_reflection_aliases(tree: ast.AST) -> set[str]:
    aliases = set(_REFLECTIVE_CALLS)
    nodes = list(ast.walk(tree))
    changed = True
    while changed:
        changed = False
        for node in nodes:
            if isinstance(node, ast.ImportFrom):
                if node.module == "builtins":
                    for alias in node.names:
                        if alias.name in _REFLECTIVE_CALLS:
                            bound = alias.asname or alias.name
                            if bound not in aliases:
                                aliases.add(bound)
                                changed = True
                elif node.module in {"inspect", "sys"}:
                    for alias in node.names:
                        if alias.name in {"currentframe", "_getframe", "stack", "getouterframes", "getframeinfo"}:
                            bound = alias.asname or alias.name
                            if bound not in aliases:
                                aliases.add(bound)
                                changed = True
            elif isinstance(node, ast.Assign):
                source_name = None
                if isinstance(node.value, ast.Name) and node.value.id in aliases:
                    source_name = node.value.id
                elif isinstance(node.value, ast.Attribute) and (
                    node.value.attr in _REFLECTIVE_CALLS or node.value.attr in _REFLECTIVE_ATTRS
                ):
                    source_name = node.value.attr
                if source_name:
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id not in aliases:
                            aliases.add(target.id)
                            changed = True
    return aliases


def obfuscate_data_flow(source: str) -> tuple[str, DataFlowObfuscationReport]:
    """Reshape eligible function-local assignments; leave unsafe scopes intact."""
    report = DataFlowObfuscationReport()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        report.skip("parse-failed")
        return source, report

    pool = _NamePool(tree)
    inherited_aliases = _collect_module_reflection_aliases(tree)
    # Start at module-level functions and class definitions. Module-level
    # assignment statements are never transformed.
    def visit_module_item(item: ast.stmt) -> None:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _transform_function(item, pool, report, inherited_aliases)
        elif isinstance(item, ast.ClassDef):
            visitor = _FunctionBodyTransformer(pool, report, inherited_aliases)
            visitor.visit_ClassDef(item)
        elif isinstance(item, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
            # Definitions nested in module control-flow blocks are processed;
            # assignments in those blocks are left unchanged.
            for child in ast.iter_child_nodes(item):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    visit_module_item(child)
                elif isinstance(child, ast.stmt):
                    visit_module_item(child)

    for item in tree.body:
        visit_module_item(item)

    if not (report.temporary_routes or report.tuple_routes):
        return source, report
    ast.fix_missing_locations(tree)
    try:
        transformed = ast.unparse(tree) + "\n"
        compile(transformed, "<data-flow-obfuscation>", "exec")
    except (SyntaxError, ValueError, TypeError):
        report.skip("transformed-source-invalid")
        return source, report
    return transformed, report
