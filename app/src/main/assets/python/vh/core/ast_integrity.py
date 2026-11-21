"""Static AST integrity checks for the PyObfuscator source pipeline.

This module never executes user code and never rewrites source.  It validates
that each intermediate artifact is valid Python and that transformations
which are not supposed to alter documentation do not silently drop module,
class, or function docstrings.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


class ASTIntegrityError(ValueError):
    """Raised when a source artifact fails a static integrity check."""


@dataclass(frozen=True)
class ASTIntegrityReport:
    stage: str
    node_count: int
    function_count: int
    async_function_count: int
    class_count: int
    import_count: int
    future_import_count: int
    definition_docstring_count: int
    module_docstring_present: bool


@dataclass(frozen=True)
class DocstringContract:
    module_present: bool
    module_value: str | None
    definition_values: tuple[tuple[str, str], ...]

    @property
    def definition_count(self) -> int:
        return len(self.definition_values)


def _target_contains_name(target: ast.expr, expected: str) -> bool:
    if isinstance(target, ast.Name):
        return target.id == expected
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_contains_name(item, expected) for item in target.elts)
    return False


def _module_docstring_info(tree: ast.Module) -> tuple[bool, str | None]:
    """Read a normal module docstring or the explicit __doc__ assignment
    created by the future-import extraction stage.
    """
    value = ast.get_docstring(tree, clean=False)
    if value is not None:
        return True, value

    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            if any(_target_contains_name(target, "__doc__") for target in statement.targets):
                literal = statement.value.value if isinstance(statement.value, ast.Constant) else None
                return True, literal if isinstance(literal, str) else None
        elif isinstance(statement, ast.AnnAssign) and _target_contains_name(statement.target, "__doc__"):
            literal = statement.value.value if isinstance(statement.value, ast.Constant) else None
            return True, literal if isinstance(literal, str) else None
    return False, None


def _definition_docstrings(tree: ast.AST) -> tuple[tuple[str, str], ...]:
    values: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            value = ast.get_docstring(node, clean=False)
            if value is not None:
                kind = type(node).__name__
                values.append((kind, value))
    return tuple(values)


def capture_docstring_contract(source: str, *, stage: str = "source") -> DocstringContract:
    """Capture docstring data without executing the supplied source."""
    try:
        tree = ast.parse(source, filename=f"<{stage}>")
    except SyntaxError as exc:
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: syntax error at line {exc.lineno}, "
            f"column {exc.offset}: {exc.msg}"
        ) from exc
    module_present, module_value = _module_docstring_info(tree)
    return DocstringContract(
        module_present=module_present,
        module_value=module_value,
        definition_values=_definition_docstrings(tree),
    )


def validate_source(
    source: str,
    *,
    stage: str,
    filename: str = "<pyobf-generated>",
) -> ASTIntegrityReport:
    """Parse and compile source without executing it; return basic AST stats."""
    if not isinstance(source, str):
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: expected source str, got {type(source).__name__}"
        )
    try:
        tree = ast.parse(source, filename=filename, mode="exec", type_comments=True)
        # compile() catches contextual errors that parsing alone may not catch
        # (for example, return/break in an invalid scope).  It does not run code.
        compile(tree, filename, "exec", dont_inherit=True)
    except SyntaxError as exc:
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: syntax/compile error at line {exc.lineno}, "
            f"column {exc.offset}: {exc.msg}"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise ASTIntegrityError(f"AST integrity [{stage}]: {exc}") from exc

    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    async_functions = [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)]
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    future_imports = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "__future__"]
    module_doc_present, _ = _module_docstring_info(tree)

    return ASTIntegrityReport(
        stage=stage,
        node_count=sum(1 for _ in ast.walk(tree)),
        function_count=len(functions),
        async_function_count=len(async_functions),
        class_count=len(classes),
        import_count=len(imports),
        future_import_count=len(future_imports),
        definition_docstring_count=len(_definition_docstrings(tree)),
        module_docstring_present=module_doc_present,
    )


def assert_docstring_contract(
    expected: DocstringContract,
    actual_source: str,
    *,
    stage: str,
) -> None:
    """Ensure a source-to-source pass preserved all docstring semantics."""
    actual = capture_docstring_contract(actual_source, stage=stage)
    if actual.module_present != expected.module_present:
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: module __doc__ presence changed "
            f"({expected.module_present} -> {actual.module_present})"
        )
    if (
        expected.module_value is not None
        and actual.module_value is not None
        and actual.module_value != expected.module_value
    ):
        raise ASTIntegrityError(f"AST integrity [{stage}]: module __doc__ value changed")
    if actual.definition_values != expected.definition_values:
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: function/class docstrings changed "
            f"({expected.definition_count} expected, {actual.definition_count} found)"
        )


def assert_module_doc_assignment(source: str, *, stage: str) -> None:
    """Verify an extracted module docstring remains represented at module scope."""
    try:
        tree = ast.parse(source, filename=f"<{stage}>")
    except SyntaxError as exc:
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: cannot inspect module __doc__: {exc}"
        ) from exc
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
            _target_contains_name(target, "__doc__") for target in statement.targets
        ):
            return
        if isinstance(statement, ast.AnnAssign) and _target_contains_name(statement.target, "__doc__"):
            return
    raise ASTIntegrityError(
        f"AST integrity [{stage}]: module docstring was present in the input, "
        "but no module-level __doc__ assignment survived the transform"
    )


def _has_docstring_restore_decorator(node: ast.AST) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Lambda):
            continue
        for child in ast.walk(decorator):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "setattr"
                and len(child.args) == 3
            ):
                return True
    return False


def assert_docstring_restore_hooks(
    source: str,
    *,
    expected_count: int,
    stage: str,
) -> None:
    """Check that string-encryption's docstring restoration decorators exist."""
    try:
        tree = ast.parse(source, filename=f"<{stage}>")
    except SyntaxError as exc:
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: cannot inspect docstring restoration hooks: {exc}"
        ) from exc
    found = sum(1 for node in ast.walk(tree) if _has_docstring_restore_decorator(node))
    if found < expected_count:
        raise ASTIntegrityError(
            f"AST integrity [{stage}]: expected at least {expected_count} docstring "
            f"restoration hooks, found {found}"
        )
