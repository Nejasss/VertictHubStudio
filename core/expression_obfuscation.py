"""Conservative expression-shape obfuscation for Python truth-test contexts.

The pass rewrites only expressions whose value is consumed solely for truthiness:
``if``, ``while``, conditional-expression tests, ``assert``, comprehension filters,
and match guards.  It uses double-negation or De Morgan transformations, which
preserve evaluation order, short-circuiting, and one truth-value check per operand.

Boolean expressions used as ordinary values (for example ``x = a and b``) are
intentionally left untouched because Python's ``and``/``or`` return an operand,
not necessarily a bool.  This pass introduces no runtime helper or new names.
It is opt-in and OFF by default.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class ExpressionObfuscationReport:
    transformed_tests: int = 0
    demorgan_tests: int = 0
    double_negation_tests: int = 0
    skipped_already_normalized: int = 0
    transformed_by_context: dict[str, int] = field(default_factory=dict)



def _not(node: ast.expr, source: ast.AST) -> ast.UnaryOp:
    return ast.copy_location(ast.UnaryOp(op=ast.Not(), operand=node), source)


def _is_double_negation(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and isinstance(node.operand, ast.UnaryOp)
        and isinstance(node.operand.op, ast.Not)
    )


def _is_demorgan_form(node: ast.expr) -> bool:
    if not (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and isinstance(node.operand, ast.BoolOp)
    ):
        return False
    inner = node.operand
    return all(
        isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not)
        for value in inner.values
    ) and isinstance(inner.op, (ast.And, ast.Or))


def _is_already_normalized(node: ast.expr) -> bool:
    return _is_double_negation(node) or _is_demorgan_form(node)


def _rewrite_truth_test(node: ast.expr) -> tuple[ast.expr, str | None]:
    """Return an equivalent bool-valued expression and the rewrite kind.

    This function is called only when the original expression is used as a
    truth test. It never duplicates an operand, so side effects and evaluation
    order are retained.
    """
    if _is_already_normalized(node):
        return node, None

    if isinstance(node, ast.BoolOp):
        # De Morgan: truth(a and b) == not (not a or not b), and likewise
        # for OR. Each original operand appears exactly once and in order.
        opposite = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        negated_values = [_not(value, value) for value in node.values]
        inner = ast.copy_location(
            ast.BoolOp(op=opposite, values=negated_values), node
        )
        return _not(inner, node), "demorgan"

    # In a truth-test position, the operand's truth value is all that matters.
    # Double negation performs that truth conversion once and produces a bool.
    return _not(_not(node, node), node), "double_negation"


class _ExpressionTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.report = ExpressionObfuscationReport()

    def _visit_test(self, node: ast.expr, context: str) -> ast.expr:
        rewritten, kind = _rewrite_truth_test(node)
        if kind is None:
            self.report.skipped_already_normalized += 1
            return self.generic_visit(rewritten)
        self.report.transformed_tests += 1
        if kind == "demorgan":
            self.report.demorgan_tests += 1
        else:
            self.report.double_negation_tests += 1
        self.report.transformed_by_context[context] = (
            self.report.transformed_by_context.get(context, 0) + 1
        )
        # Visit nested expressions after wrapping. They may contain their own
        # conditional expressions/comprehensions, but the generated negations
        # themselves are not truth-test contexts and are not rewritten again.
        return self.generic_visit(rewritten)

    def visit_If(self, node: ast.If):
        node.test = self._visit_test(node.test, "if")
        node.body = [self.visit(item) for item in node.body]
        node.orelse = [self.visit(item) for item in node.orelse]
        return node

    def visit_While(self, node: ast.While):
        node.test = self._visit_test(node.test, "while")
        node.body = [self.visit(item) for item in node.body]
        node.orelse = [self.visit(item) for item in node.orelse]
        return node

    def visit_IfExp(self, node: ast.IfExp):
        node.test = self._visit_test(node.test, "conditional-expression")
        node.body = self.visit(node.body)
        node.orelse = self.visit(node.orelse)
        return node

    def visit_Assert(self, node: ast.Assert):
        node.test = self._visit_test(node.test, "assert")
        if node.msg is not None:
            node.msg = self.visit(node.msg)
        return node

    def visit_comprehension(self, node: ast.comprehension):
        node.target = self.visit(node.target)
        node.iter = self.visit(node.iter)
        node.ifs = [self._visit_test(item, "comprehension-filter") for item in node.ifs]
        return node

    def visit_match_case(self, node):
        node.pattern = self.visit(node.pattern)
        if node.guard is not None:
            node.guard = self._visit_test(node.guard, "match-guard")
        node.body = [self.visit(item) for item in node.body]
        return node


def obfuscate_expressions(source: str) -> tuple[str, ExpressionObfuscationReport]:
    """Transform supported truth-test expressions; return source and report.

    If parsing fails or no eligible condition exists, source is returned
    unchanged. The caller is responsible for normal AST validation at pipeline
    boundaries.
    """
    report = ExpressionObfuscationReport()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return source, report

    transformer = _ExpressionTransformer()
    transformed = transformer.visit(tree)
    report = transformer.report
    if report.transformed_tests == 0:
        return source, report

    ast.fix_missing_locations(transformed)
    return ast.unparse(transformed) + "\n", report
