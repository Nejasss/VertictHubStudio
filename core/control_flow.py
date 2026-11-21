"""Conservative, opt-in control-flow flattening for simple function bodies.

This module intentionally transforms only functions that contain exactly one
if-statement directly in their body. The if/elif/else branches are moved into
an integer-state dispatcher; statements before the if stay before it, and
statements after it become the continuation state.

Functions using dynamic local-scope/frame introspection are skipped because an
extra dispatcher variable/loop would be observable through those APIs. The
transform is deliberately optional and defaults OFF in ObfuscationConfig.
"""
from __future__ import annotations

import ast
import secrets


_DYNAMIC_SCOPE_CALLS = {"locals", "vars", "eval", "exec"}
_DYNAMIC_FRAME_ATTRS = {"_getframe", "currentframe", "f_locals"}


def _uses_dynamic_scope_or_frames(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id in _DYNAMIC_SCOPE_CALLS:
                return True
            if isinstance(child.func, ast.Attribute) and child.func.attr in _DYNAMIC_FRAME_ATTRS:
                return True
        if isinstance(child, ast.Attribute) and child.attr in _DYNAMIC_FRAME_ATTRS:
            return True
    return False


def _existing_identifiers(node: ast.AST) -> set[str]:
    used: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            used.add(child.id)
        elif isinstance(child, ast.arg):
            used.add(child.arg)
        elif isinstance(child, (ast.Global, ast.Nonlocal)):
            used.update(child.names)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            used.add(child.name)
        elif isinstance(child, ast.alias):
            used.add(child.asname or child.name.split(".", 1)[0])
        elif isinstance(child, ast.ExceptHandler) and child.name:
            used.add(child.name)
        elif isinstance(child, ast.MatchAs) and child.name:
            used.add(child.name)
        elif isinstance(child, ast.MatchStar) and child.name:
            used.add(child.name)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            used.add(child.rest)
        elif isinstance(child, ast.keyword) and child.arg:
            used.add(child.arg)
    return used


def _fresh_state_name(node: ast.AST) -> str:
    used = _existing_identifiers(node)
    while True:
        candidate = f"_vh_cfo_state_{secrets.token_hex(3)}"
        if candidate not in used:
            return candidate


def _state_name(name: str, ctx: ast.expr_context = ast.Load()) -> ast.Name:
    return ast.Name(id=name, ctx=ctx)


def _state_assign(name: str, value: int, source_node: ast.AST) -> ast.Assign:
    return ast.copy_location(
        ast.Assign(
            targets=[_state_name(name, ast.Store())],
            value=ast.Constant(value=value),
        ),
        source_node,
    )


def _state_test(name: str, value: int, source_node: ast.AST) -> ast.Compare:
    return ast.copy_location(
        ast.Compare(
            left=_state_name(name),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=value)],
        ),
        source_node,
    )


def _extract_branches(if_node: ast.If) -> list[tuple[ast.expr | None, list[ast.stmt]]]:
    """Return ordered (condition, body) branches, including implicit else."""
    branches: list[tuple[ast.expr | None, list[ast.stmt]]] = []
    current = if_node
    while True:
        branches.append((current.test, current.body))
        if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
            current = current.orelse[0]
            continue
        branches.append((None, current.orelse))
        return branches


def _build_dispatcher(
    function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    if_node: ast.If,
    branches: list[tuple[ast.expr | None, list[ast.stmt]]],
    tail: list[ast.stmt],
) -> ast.While:
    state_name = _fresh_state_name(function_node)
    dispatch_cases: list[tuple[int, list[ast.stmt]]] = []

    # State 0 evaluates the original if/elif tests once, in their original
    # order, and selects the branch state. The branch bodies themselves run
    # on the next dispatcher iteration.
    condition_branches = [(test, index + 1) for index, (test, _body) in enumerate(branches) if test is not None]
    default_state = next(
        (index + 1 for index, (test, _body) in enumerate(branches) if test is None),
        len(branches),
    )

    selection: ast.If | None = None
    current_selection: ast.If | None = None
    for test, target_state in condition_branches:
        node = ast.copy_location(
            ast.If(
                test=test,
                body=[_state_assign(state_name, target_state, if_node)],
                orelse=[],
            ),
            if_node,
        )
        if selection is None:
            selection = node
        else:
            assert current_selection is not None
            current_selection.orelse = [node]
        current_selection = node
    assert selection is not None
    current_selection.orelse = [_state_assign(state_name, default_state, if_node)]
    dispatch_cases.append((0, [selection]))

    continuation_state = len(branches) + 1
    for index, (_test, body) in enumerate(branches, start=1):
        # An explicit return/raise naturally exits before the state update;
        # normal fall-through advances to the shared continuation.
        branch_body = list(body) + [_state_assign(state_name, continuation_state, if_node)]
        dispatch_cases.append((index, branch_body))

    continuation_body = list(tail) + [ast.copy_location(ast.Break(), if_node)]
    dispatch_cases.append((continuation_state, continuation_body))

    case_chain: ast.If | None = None
    current_case: ast.If | None = None
    for state_value, case_body in dispatch_cases:
        case = ast.copy_location(
            ast.If(
                test=_state_test(state_name, state_value, if_node),
                body=case_body,
                orelse=[],
            ),
            if_node,
        )
        if case_chain is None:
            case_chain = case
        else:
            assert current_case is not None
            current_case.orelse = [case]
        current_case = case

    assert current_case is not None
    current_case.orelse = [
        ast.copy_location(
            ast.Raise(
                exc=ast.Call(
                    func=ast.Name(id="RuntimeError", ctx=ast.Load()),
                    args=[ast.Constant("invalid control-flow state")],
                    keywords=[],
                ),
                cause=None,
            ),
            if_node,
        )
    ]

    initial_state = _state_assign(state_name, 0, if_node)
    loop = ast.copy_location(
        ast.While(
            test=ast.Constant(value=True),
            body=[case_chain],
            orelse=[],
        ),
        if_node,
    )
    # Return a tiny wrapper block as a While with an initial assignment
    # prepended by the caller via the private attribute below.
    loop._vh_initial_state = initial_state  # type: ignore[attr-defined]
    return loop


class _ControlFlowFlattener(ast.NodeTransformer):
    def __init__(self) -> None:
        self.transformed_functions = 0

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.generic_visit(node)
        self._flatten_function(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.generic_visit(node)
        self._flatten_function(node)
        return node

    def _flatten_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if _uses_dynamic_scope_or_frames(node):
            return

        body = node.body
        docstring_prefix: list[ast.stmt] = []
        start_index = 0
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            docstring_prefix = [body[0]]
            start_index = 1

        direct_if_positions = [
            index for index in range(start_index, len(body))
            if isinstance(body[index], ast.If)
        ]
        # Conservative v1: one direct if/elif/else per function. Complex
        # functions are left byte-for-byte semantically unchanged.
        if len(direct_if_positions) != 1:
            return

        if_index = direct_if_positions[0]
        if_node = body[if_index]
        assert isinstance(if_node, ast.If)
        branches = _extract_branches(if_node)
        tail = body[if_index + 1:]
        loop = _build_dispatcher(node, if_node, branches, tail)
        initial_state = loop._vh_initial_state  # type: ignore[attr-defined]
        delattr(loop, "_vh_initial_state")
        node.body = docstring_prefix + body[start_index:if_index] + [initial_state, loop]
        self.transformed_functions += 1


def obfuscate_control_flow(source: str) -> str:
    """Flatten eligible function-level if/elif/else blocks.

    Invalid/incomplete source is returned untouched. The caller should run
    its normal compile/build validation after this transformation.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    transformer = _ControlFlowFlattener()
    transformed = transformer.visit(tree)
    if transformer.transformed_functions == 0:
        return source
    ast.fix_missing_locations(transformed)
    return ast.unparse(transformed) + "\n"
