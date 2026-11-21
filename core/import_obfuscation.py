"""Conservative dynamic-import rewriting for Python source obfuscation.

The pass rewrites eligible absolute ``import`` and ``from ... import ...``
statements into calls to the built-in ``__import__``.  Module/member names are
ordinary string constants at this stage, so the existing String Encryption pass
can protect them later in the pipeline.

Deliberately unsupported in v1:
* relative imports (package-context-sensitive),
* star imports (dynamic namespace population),
* aliased dotted imports (``import a.b as c`` has special binding semantics),
* modules that bind ``__import__``, which is needed for generated calls.

The pass is opt-in and does not execute user code.
"""
from __future__ import annotations

import ast
import secrets
from dataclasses import dataclass, field


@dataclass
class ImportObfuscationReport:
    transformed_import_statements: int = 0
    transformed_from_statements: int = 0
    transformed_aliases: int = 0
    skipped_relative_imports: int = 0
    skipped_star_imports: int = 0
    skipped_dotted_aliases: int = 0
    skipped_shadowed_builtins: bool = False
    parse_failed: bool = False
    # Names bound by generated assignments. The legacy identifier pass did
    # not rename import aliases (they are ast.alias nodes), so preserve these
    # names to retain reflective import behavior after this pass rewrites them.
    preserved_names: set[str] = field(default_factory=set)

    @property
    def transformed_total(self) -> int:
        return self.transformed_import_statements + self.transformed_from_statements


_RESERVED_BUILTINS = {"__import__"}


class _BindingScanner(ast.NodeVisitor):
    """Find source-level bindings that could shadow generated built-ins."""

    def __init__(self) -> None:
        self.bound: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound.add(node.id)

    def visit_arg(self, node: ast.arg) -> None:
        self.bound.add(node.arg)
        if node.annotation is not None:
            self.visit(node.annotation)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bound.add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bound.add(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bound.add(node.name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.bound.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.bound.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.bound.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.bound.update(node.names)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.bound.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.bound.add(node.rest)
        self.generic_visit(node)


def _call(name: str, args: list[ast.expr], keywords=None, source=None) -> ast.Call:
    node = ast.Call(
        func=ast.Name(id=name, ctx=ast.Load()),
        args=args,
        keywords=list(keywords or []),
    )
    return ast.copy_location(node, source) if source is not None else node


def _name(value: str, ctx: ast.expr_context, source=None) -> ast.Name:
    node = ast.Name(id=value, ctx=ctx)
    return ast.copy_location(node, source) if source is not None else node


def _constant(value, source=None) -> ast.Constant:
    node = ast.Constant(value=value)
    return ast.copy_location(node, source) if source is not None else node


def _tuple_of_strings(values: list[str], source=None) -> ast.Tuple:
    node = ast.Tuple(
        elts=[_constant(value, source) for value in values],
        ctx=ast.Load(),
    )
    return ast.copy_location(node, source) if source is not None else node


class _ImportTransformer(ast.NodeTransformer):
    def __init__(self, report: ImportObfuscationReport, used_names: set[str]) -> None:
        self.report = report
        self.used_names = set(used_names)

    def _fresh_temp(self) -> str:
        while True:
            name = "__obf_import_" + secrets.token_hex(6)
            if name not in self.used_names:
                self.used_names.add(name)
                return name

    def visit_Import(self, node: ast.Import):
        rewritten: list[ast.stmt] = []
        for alias in node.names:
            # ``import a.b as c`` is compiled as a top-level import followed
            # by IMPORT_FROM operations.  Returning the leaf module directly
            # would subtly change package attribute lookup, so leave it alone.
            if alias.asname and "." in alias.name:
                self.report.skipped_dotted_aliases += 1
                rewritten.append(ast.copy_location(
                    ast.Import(names=[ast.alias(name=alias.name, asname=alias.asname)]), node
                ))
                continue

            target = alias.asname or alias.name.split(".", 1)[0]
            self.report.preserved_names.add(target)
            call = _call(
                "__import__",
                [_constant(alias.name, node)],
                source=node,
            )
            assign = ast.Assign(
                targets=[_name(target, ast.Store(), node)],
                value=call,
            )
            rewritten.append(ast.copy_location(assign, node))
            self.report.transformed_import_statements += 1
            self.report.transformed_aliases += 1
        return rewritten

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "__future__":
            return node
        if node.level:
            self.report.skipped_relative_imports += 1
            return node
        if any(alias.name == "*" for alias in node.names):
            self.report.skipped_star_imports += 1
            return node
        if not node.names:
            return node

        module_name = node.module or ""
        from_names = [alias.name for alias in node.names]
        temp_name = self._fresh_temp()
        self.report.preserved_names.add(temp_name)
        module_call = _call(
            "__import__",
            [_constant(module_name, node)],
            keywords=[ast.keyword(
                arg="fromlist",
                value=_tuple_of_strings(from_names, node),
            )],
            source=node,
        )
        statements: list[ast.stmt] = [ast.copy_location(
            ast.Assign(
                targets=[_name(temp_name, ast.Store(), node)],
                value=module_call,
            ),
            node,
        )]

        for alias in node.names:
            target_name = alias.asname or alias.name
            self.report.preserved_names.add(target_name)
            module_type_getattribute = ast.Attribute(
                value=ast.Attribute(
                    value=_name(temp_name, ast.Load(), node),
                    attr="__class__",
                    ctx=ast.Load(),
                ),
                attr="__getattribute__",
                ctx=ast.Load(),
            )
            module_type_getattribute = ast.copy_location(module_type_getattribute, node)
            get_member = ast.copy_location(
                ast.Call(
                    func=module_type_getattribute,
                    args=[_name(temp_name, ast.Load(), node), _constant(alias.name, node)],
                    keywords=[],
                ),
                node,
            )
            statements.append(ast.copy_location(
                ast.Assign(
                    targets=[_name(target_name, ast.Store(), node)],
                    value=get_member,
                ),
                node,
            ))

        statements.append(ast.copy_location(
            ast.Delete(targets=[_name(temp_name, ast.Del(), node)]),
            node,
        ))
        self.report.transformed_from_statements += 1
        self.report.transformed_aliases += len(node.names)
        return statements


def obfuscate_imports(source: str) -> tuple[str, ImportObfuscationReport]:
    """Rewrite supported imports; return transformed source and a report.

    A module is left entirely unchanged if it binds either generated builtin
    name (`__import__` or `getattr`).  This avoids accidental name capture in
    function, class, and module scopes.  Relative imports, star imports, and
    aliased dotted imports are skipped individually.
    """
    report = ImportObfuscationReport()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        report.parse_failed = True
        return source, report

    scanner = _BindingScanner()
    scanner.visit(tree)
    if scanner.bound & _RESERVED_BUILTINS:
        report.skipped_shadowed_builtins = True
        return source, report

    used_names = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    used_names.update(
        node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)
    )
    used_names.update(
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    transformer = _ImportTransformer(report, used_names)
    transformed = transformer.visit(tree)
    if report.transformed_total == 0:
        return source, report

    ast.fix_missing_locations(transformed)
    try:
        compile(transformed, "<import-obfuscation>", "exec")
    except (SyntaxError, ValueError, TypeError):
        # A transformation must never hand invalid Python to later passes.
        # Fail closed by returning the exact original source.
        return source, ImportObfuscationReport(parse_failed=True)
    return ast.unparse(transformed) + "\n", report
