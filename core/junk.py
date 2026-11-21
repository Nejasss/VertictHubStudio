"""
junk.py - generates syntactically valid but semantically meaningless
Python source (dead functions, opaque predicates, fake classes, and
decoy methods spliced into real classes) to bloat the bytecode and
waste an analyst's time when reversing.

Naming note: junk names use the exact same format as
identifier_rename.py's renamed identifiers ("_" + 10 lowercase-
letters-and-digits) specifically so that, once both passes have run,
a decoy name and a real-but-renamed name are visually
indistinguishable in a `strings`/disassembly dump - there's no
"junk uses short all-letter names, real renamed code uses a longer
mixed format" tell to filter on.
"""
import ast
import random
import string


def _rand_name(n=10):
    return "_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _rand_junk_function():
    name = _rand_name()
    a, b = _rand_name(4), _rand_name(4)
    op = random.choice(["+", "-", "*", "^", "&", "|"])
    body_lines = [
        f"def {name}({a}={random.randint(1,999)}, {b}={random.randint(1,999)}):",
        f"    _t = {a} {op} {b}",
        f"    for _i in range({random.randint(1,5)}):",
        f"        _t = (_t {op} _i) % {random.randint(97, 65535)}",
        f"    if _t == -1:",
        f"        return None",
        f"    return _t",
    ]
    return "\n".join(body_lines)


def _rand_junk_class():
    name = _rand_name()
    m1, m2 = _rand_name(5), _rand_name(5)
    lines = [
        f"class {name}:",
        f"    def __init__(self):",
        f"        self.{m1} = {random.randint(1, 9999)}",
        f"    def {m2}(self):",
        f"        return self.{m1} ^ {random.randint(1, 9999)}",
    ]
    return "\n".join(lines)


def _opaque_predicate_guard():
    """
    An always-false condition that looks data-dependent, wrapping a
    call to a junk function. Confuses control-flow reconstruction in
    decompilers that try to simplify branches.
    """
    fn = _rand_junk_function()
    name = fn.split("(")[0].split(" ")[1]
    x = random.randint(2, 50)
    guard = f"({x} * {x}) % {x} == 1"  # always false for x>1
    lines = [
        fn,
        f"if {guard}:",
        f"    {name}()",
    ]
    return "\n".join(lines)


def generate_junk_block(intensity: int = 5) -> str:
    """
    intensity: roughly how many junk constructs to emit (1-20 sane range)
    """
    parts = []
    for _ in range(max(1, intensity)):
        choice = random.choice(["func", "class", "guard"])
        if choice == "func":
            parts.append(_rand_junk_function())
        elif choice == "class":
            parts.append(_rand_junk_class())
        else:
            parts.append(_opaque_predicate_guard())
    return "\n\n".join(parts) + "\n"


def _rand_junk_method(self_name: str = "self") -> str:
    """
    A decoy method meant to be spliced INTO an existing (real) class,
    not to stand alone. Reads/writes a fake attribute on self so it
    at least LOOKS like it participates in the object's state, the
    same way a real method would - a junk method that never touches
    self is a much easier tell (in co_names / bytecode) than one that
    superficially behaves like the real methods around it.
    """
    name = _rand_name()
    attr = _rand_name(6)
    b = _rand_name(4)
    op = random.choice(["+", "-", "*", "^"])
    lines = [
        f"def {name}({self_name}, {b}={random.randint(1, 999)}):",
        f"    if not hasattr({self_name}, {attr!r}):",
        f"        {self_name}.{attr} = {random.randint(1, 9999)}",
        f"    {self_name}.{attr} = ({self_name}.{attr} {op} {b}) % {random.randint(97, 65535)}",
        f"    return {self_name}.{attr}",
    ]
    return "\n".join("    " + l for l in lines)


class _DecoyMethodInjector(ast.NodeTransformer):
    """
    Splices 1-3 decoy methods into every real ClassDef found in the
    source. Runs as its own AST pass so the decoy methods end up
    inside the SAME ClassDef node as the real methods - i.e. actually
    nested in the class body at the source level, not just appended
    as unrelated top-level junk - which is what makes them show up
    correctly scoped (bound to the class, callable as self.method())
    if anyone tries to actually exercise them, rather than obviously
    dangling dead code floating outside any class.
    """
    def __init__(self, min_per_class=1, max_per_class=3):
        self.min_per_class = min_per_class
        self.max_per_class = max_per_class

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        n = random.randint(self.min_per_class, self.max_per_class)
        # A class docstring has special meaning only while it remains the
        # first statement in the class body. Never insert decoy methods
        # before it, or Python will stop populating Class.__doc__.
        has_docstring = bool(
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        )
        min_position = 1 if has_docstring else 0
        for _ in range(n):
            method_src = "class _J:\n" + _rand_junk_method()
            fake_module = ast.parse(method_src)
            fake_class = fake_module.body[0]
            method_node = fake_class.body[0]
            # Insert randomly among class statements, but after a leading
            # docstring so the language-level documentation position survives.
            pos = random.randint(min_position, len(node.body))
            node.body.insert(pos, method_node)
        return node


def inject_decoy_methods(source: str, min_per_class: int = 1, max_per_class: int = 3) -> str:
    """
    Parses source, splices min_per_class..max_per_class decoy methods
    into every class defined in it, and returns the resulting source.
    No-op (returns source unchanged) if the source defines no classes.
    Call this BEFORE identifier_rename.rename_identifiers() in the
    pipeline, so the decoy method names get put through the exact
    same renaming pass as everything else - though since they're
    already generated in identifier_rename's own naming format, they
    end up looking identical either way.
    """
    tree = ast.parse(source)
    if not any(isinstance(n, ast.ClassDef) for n in ast.walk(tree)):
        return source
    injector = _DecoyMethodInjector(min_per_class, max_per_class)
    new_tree = injector.visit(tree)
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree)
