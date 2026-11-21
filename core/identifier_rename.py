"""
identifier_rename.py - renames local variables, function/method names,
and class names to random gibberish, so someone reading a decompiled/
dumped/Cython-`strings`-dumped version of the code can't skim
meaningful names like `WebsiteDumper`, `download_file`, or
`secret_key` to understand what the code does.

Why function/class names specifically matter for the Cython build
path: Cython bakes each function/method's fully-qualified name
(e.g. "mymodule.WebsiteDumper.download_file") into the compiled
binary as a plain C string literal, for traceback/introspection
support - so even though the *logic* is native machine code, those
name strings are still sitting there in cleartext for `strings
binary` to find. Renaming them before Cython ever sees the source is
the only point in the pipeline that can prevent this (nothing later
can un-bake a string that's already compiled into a C literal).

Scope (deliberately still conservative - safety over completeness):
  RENAMED:
  - any simple `Name` node in Store context (local variable/for/with-as/
    except-as/comprehension/walrus assignment targets) - as before.
  - top-level and nested `def`/`async def` function names, including
    methods inside a class body, AND every call-site/reference to
    that name found anywhere else in the same file (Name loads,
    `self.name(...)`/`cls.name(...)` and same-class `attribute`
    accesses, decorators referencing it, recursive self-calls).
  - `class` names, and the same call-site/reference rewriting as
    functions (constructor calls, base-class references, isinstance
    checks, type annotations that reference the class by name).
  - function/method parameter names (positional, keyword-only,
    *args, **kwargs) - renamed per-function-scope (not through the
    same file-wide rename_map local variables/def names use, since
    two unrelated functions can each have their own same-named
    parameter and must not collide), together with every reference
    to that parameter inside its own function body. See "NOT
    RENAMED" below for the keyword-call-site exclusion this requires
    for safety, and why param names being left alone at all used to
    be a real information leak: they survive into co_varnames in the
    compiled bytecode even after every other name in the file was
    randomized, so `dis.dis()`/decompiler output on a fully
    identifier-renamed function still showed meaningful parameter
    names like `url`, `api_key`, `save_path` - enough on their own,
    in practice, for an attacker to reconstruct what a function does
    even with zero recovered variable/function names to go with them.

  NOT RENAMED (safety-critical - renaming any of these WILL break
  the script, or breaks something outside this single file's view):
  - dunder/magic methods (__init__, __str__, __enter__, etc.) - the
    Python runtime calls these BY that exact name; renaming breaks
    the protocol silently (e.g. `__init__` stops being called at all).
  - imported names, attribute names on objects NOT proven to be an
    instance of a class defined in this same file, dict/plain-string
    keyword-argument-style dict keys, builtins, `self`/`cls`.
  - a function/method parameter whose name is ALSO used as a keyword
    argument in ANY call anywhere in the file (e.g. `def f(name):
    ...` alongside a call `f(name=x)` elsewhere, OR a call to a
    DIFFERENT function that happens to share the keyword `name=`) -
    an AST-only pass has no way to prove which `Call` node's
    `keywords` targets THIS specific function versus some other
    function/method that coincidentally shares a parameter name, so
    any parameter name seen as a keyword anywhere in the file is
    excluded from parameter renaming entirely (same
    conservative-instead-of-silently-wrong policy the string-literal
    exclusion above already uses for def/class names).
  - `*args`/`**kwargs`-style catch-all parameter names themselves
    (the vararg/kwarg slot, not the values passed through it) - left
    unrenamed even when not keyword-referenced, since they're
    frequently forwarded on to other calls (`other_func(**kwargs)`)
    or introspected by name (`kwargs.get("timeout")`) in ways an
    AST-only pass can't fully verify are safe to touch.
  - any function/class/method whose name is also referenced as a
    plain string literal anywhere in the file (e.g. getattr(obj,
    "download_file"), a dict dispatch table {"download_file": ...},
    argparse dest= strings, Flask/click route names, etc.) - AST
    renaming has no way to find and rewrite matching string literals
    safely, so any name found duplicated as a string anywhere in the
    file is excluded from renaming entirely, rather than risk
    silently desyncing the code from a string-based lookup.
  - anything defined at module scope that could plausibly be
    imported by OTHER files this tool never sees (this pass only
    ever looks at one file/source string at a time, with no
    whole-project cross-reference) - as a conservative proxy for
    this, names listed in `__all__` (if present) are never renamed,
    since that list exists specifically to declare a file's public,
    externally-used surface.
"""
import ast
import builtins
import keyword
import random
import string
from . import unicode_names

RESERVED = set(dir(builtins)) | set(keyword.kwlist) | {"self", "cls", "_", "__all__"}

# Magic/dunder methods the Python runtime invokes by exact name as
# part of its object protocols - renaming any of these breaks the
# corresponding feature outright (e.g. renamed __init__ is simply
# never called by the class constructor anymore).
DUNDER_PATTERN_IS_PROTOCOL = True  # any name matching __x__ is always excluded, see _is_dunder


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _rand_name(existing: set, n: int = 10) -> str:
    while True:
        cand = "_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
        if cand not in existing:
            return cand


def _rand_name_cjk(existing: set, n: int = 6) -> str:
    """Same contract as _rand_name (collision-avoiding, adds to no
    set itself - caller tracks `existing`), but generates CJK
    identifiers via unicode_names instead of ASCII. See that module's
    docstring for why/when to use this instead of _rand_name."""
    return unicode_names.rand_cjk_identifier_unique(existing, n)


def _collect_keyword_call_names(tree: ast.AST) -> set:
    """Every name used as `name=...` in ANY Call anywhere in the file
    - see the module docstring's parameter-renaming NOT-RENAMED entry
    for why this is the exclusion set for parameter renaming: an
    AST-only pass can't prove a given Call's keywords target this
    specific function versus some other one that happens to share a
    parameter name, so anything seen as a keyword anywhere is treated
    as possibly referencing a parameter by that exact name and left
    alone everywhere."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg is not None:  # None means **kwargs-spread, not a named kwarg
                    names.add(kw.arg)
    return names


def _collect_param_names(tree: ast.AST) -> set:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            for arglist in (a.posonlyargs, a.args, a.kwonlyargs):
                for arg in arglist:
                    names.add(arg.arg)
            if a.vararg:
                names.add(a.vararg.arg)
            if a.kwarg:
                names.add(a.kwarg.arg)
    return names


def _collect_string_literals(tree: ast.AST) -> set:
    """Every plain string constant anywhere in the file - used to
    exclude any function/class name that's also referenced as a
    string (getattr/dispatch-table/route-name/etc. patterns this
    AST-only pass can't safely follow and rewrite)."""
    lits = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            lits.add(node.value)
    return lits


def _collect_dunder_all_names(tree: ast.AST) -> set:
    """Names listed in a module-level `__all__ = [...]` assignment -
    treated as this file's declared public surface and never renamed,
    since other files this pass never sees may import them by name."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if "__all__" in targets and isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        names.add(elt.value)
    return names


def _collect_def_names(tree: ast.AST, string_lits: set, public_names: set) -> set:
    """Function, async function, and class names - excluding dunders,
    anything also seen as a string literal, anything declared in
    ``__all__``, and any name also used as a parameter anywhere in the
    file.

    The last exclusion is important because this renamer deliberately
    uses a file-wide map for def/class names.  If ``Player.value`` and
    ``def branch(value)`` coexist, globally renaming the method name
    also rewrites every ``Name('value')`` load in ``branch`` before the
    per-function parameter pass runs.  The arg node remains unchanged,
    so the body then refers to a different identifier and raises
    ``NameError`` (or fails Cython's undeclared-name analysis).  There
    is no safe file-wide way to distinguish those meanings without a
    full scope-aware symbol resolver.  Conservatively leaving that def
    name unchanged lets the parameter pass rename its own scope
    consistently, including the case where keyword-call safety forces
    the parameter to remain unchanged.
    """
    parameter_names = _collect_param_names(tree)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            n = node.name
            if _is_dunder(n):
                continue
            if n in string_lits:
                continue
            if n in public_names:
                continue
            if n in parameter_names:
                continue
            names.add(n)
    return names - RESERVED


def _collect_class_body_attr_names(tree: ast.AST) -> set:
    """Names assigned directly in a `class Foo: ...` body - i.e. class
    attributes/constants like `ID_RANGES = [...]` sitting alongside
    method defs, NOT inside `__init__`/any method body. These are
    `ast.Name` nodes in Store context exactly like a local variable,
    so `_collect_store_names` would otherwise sweep them into
    rename_map and rename the DEFINITION - but any `self.ID_RANGES`/
    `ClassName.ID_RANGES` reference to them is an `ast.Attribute`
    node, and visit_Attribute only rewrites attrs found in
    attr_rename_map (def/class names only, see IdentifierRenamer's
    docstring) - so the reference side never gets renamed to match,
    desyncing definition from every usage and breaking the class with
    an AttributeError at runtime. Safest fix (consistent with this
    module's conservative-over-complete policy): never rename a
    class-body-level assignment target at all, same as def/class
    names and params already get their own exclusion.
    """
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                targets = []
                if isinstance(stmt, ast.Assign):
                    targets = stmt.targets
                elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                    targets = [stmt.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        names.add(t.id)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for elt in t.elts:
                            if isinstance(elt, ast.Name):
                                names.add(elt.id)
    return names


def _collect_store_names(tree: ast.AST) -> set:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    # Critical: a name that's ALSO used as a function parameter anywhere
    # must never be renamed here, since parameters themselves are
    # intentionally left untouched (see module docstring). If a local
    # variable happens to share a parameter's name - extremely common,
    # e.g. `def f(x): x = x.strip()` - renaming only the reassignment
    # target desyncs it from the untouched parameter and breaks the
    # function (NameError / "referenced before assignment").
    names -= _collect_param_names(tree)
    # Class-body-level constants (ID_RANGES = [...] directly in a
    # class, not in a method) must never be renamed - see
    # _collect_class_body_attr_names docstring for why.
    names -= _collect_class_body_attr_names(tree)
    return names - RESERVED


class _LocalInstanceReceiverScanner(ast.NodeVisitor):
    """Find simple, unambiguous local variables assigned to local classes.

    Only a single direct assignment such as ``worker = Worker()`` is
    accepted. Parameters, repeated writes, nested scopes, attributes and
    aliases are deliberately excluded: a false negative merely preserves
    a method name, while a false positive can break an external API call.
    """
    def __init__(self, root, class_methods_by_name):
        self.root = root
        self.class_methods_by_name = class_methods_by_name
        self.write_counts = {}
        self.candidates = {}

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.write_counts[node.id] = self.write_counts.get(node.id, 0) + 1

    def _record_assignment(self, targets, value):
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)):
            return
        methods = self.class_methods_by_name.get(value.func.id)
        if methods is None:
            return
        for target in targets:
            if isinstance(target, ast.Name):
                self.candidates[target.id] = methods

    def visit_Assign(self, node):
        self._record_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._record_assignment([node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node is self.root:
            for statement in node.body:
                self.visit(statement)
        # Nested functions have independent local scopes.

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Lambda(self, node):
        return

    def visit_ClassDef(self, node):
        return

    def proven_receivers(self, parameter_names):
        return {
            name: methods
            for name, methods in self.candidates.items()
            if self.write_counts.get(name) == 1 and name not in parameter_names
        }


def _collect_class_method_info(tree):
    """Return per-class method sets and unambiguous class-name lookups."""
    by_node = {}
    by_method_node = {}
    name_groups = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        methods = frozenset(
            statement.name
            for statement in node.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        by_node[id(node)] = methods
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                by_method_node[id(statement)] = methods
        name_groups.setdefault(node.name, []).append(methods)

    by_name = {
        name: groups[0]
        for name, groups in name_groups.items()
        if len(groups) == 1
    }
    return by_node, by_name, by_method_node


class IdentifierRenamer(ast.NodeTransformer):
    """Rename identifiers while only rewriting proven local-class methods.

    Attribute names are no longer rewritten globally. ``obj.method`` is
    changed only when ``obj`` is statically known to be ``self``/``cls`` of
    the owning class, a uniquely named local class, a direct constructor
    result stored once in a local variable, or a direct constructor call.
    Unknown receivers (including threading.Thread/Timer instances and
    attributes such as ``self.reader``) keep their original API names.
    """
    def __init__(self, rename_map: dict, attr_rename_map: dict,
                 class_methods_by_node=None, class_methods_by_name=None,
                 class_method_nodes=None, module_instance_receivers=None):
        self.rename_map = rename_map
        self.attr_rename_map = attr_rename_map
        self.class_methods_by_node = class_methods_by_node or {}
        self.class_methods_by_name = class_methods_by_name or {}
        self.class_method_nodes = class_method_nodes or {}
        # Each scope maps proven receiver variable names to a set of methods
        # implemented by the local class they reference.
        self.receiver_scope_stack = [dict(module_instance_receivers or {})]

    def visit_Name(self, node):
        if node.id in self.rename_map:
            node.id = self.rename_map[node.id]
        return node

    def _resolve_receiver_methods(self, receiver):
        if isinstance(receiver, ast.Name):
            for scope in reversed(self.receiver_scope_stack):
                if receiver.id in scope:
                    return scope[receiver.id]
            return self.class_methods_by_name.get(receiver.id)
        if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name):
            return self.class_methods_by_name.get(receiver.func.id)
        return None

    @staticmethod
    def _parameter_names(node):
        args = node.args
        values = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        if args.vararg:
            values.append(args.vararg)
        if args.kwarg:
            values.append(args.kwarg)
        return {arg.arg for arg in values}

    def _visit_function(self, node):
        parameter_names = self._parameter_names(node)
        scope = dict(self.receiver_scope_stack[-1])
        # Function parameters and local writes shadow a captured receiver.
        for name in parameter_names:
            scope.pop(name, None)

        scanner = _LocalInstanceReceiverScanner(node, self.class_methods_by_name)
        for statement in node.body:
            scanner.visit(statement)
        for name in scanner.write_counts:
            scope.pop(name, None)
        scope.update(scanner.proven_receivers(parameter_names))

        current_methods = self.class_method_nodes.get(id(node))
        if current_methods is not None:
            decorators = {
                decorator.id
                for decorator in node.decorator_list
                if isinstance(decorator, ast.Name)
            }
            positional = list(node.args.posonlyargs) + list(node.args.args)
            if positional:
                first = positional[0].arg
                is_instance_receiver = (
                    first == "self"
                    and "staticmethod" not in decorators
                    and "classmethod" not in decorators
                )
                is_class_receiver = first == "cls" and "classmethod" in decorators
                if ((is_instance_receiver or is_class_receiver)
                        and first not in scanner.write_counts):
                    scope[first] = current_methods

        self.receiver_scope_stack.append(scope)
        try:
            if node.name in self.rename_map:
                node.name = self.rename_map[node.name]
            self.generic_visit(node)
        finally:
            self.receiver_scope_stack.pop()
        return node

    def visit_Attribute(self, node):
        # Resolve before visiting children: Name nodes may themselves be
        # renamed during generic_visit, but receiver analysis uses original
        # source identifiers and the pre-transform scope map.
        receiver_methods = self._resolve_receiver_methods(node.value)
        original_attr = node.attr
        self.generic_visit(node)
        if (receiver_methods is not None
                and original_attr in receiver_methods
                and original_attr in self.attr_rename_map):
            node.attr = self.attr_rename_map[original_attr]
        return node

    def visit_FunctionDef(self, node):
        return self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        return self._visit_function(node)

    def visit_Lambda(self, node):
        scope = dict(self.receiver_scope_stack[-1])
        for arg in (list(node.args.posonlyargs) + list(node.args.args)
                    + list(node.args.kwonlyargs)):
            scope.pop(arg.arg, None)
        if node.args.vararg:
            scope.pop(node.args.vararg.arg, None)
        if node.args.kwarg:
            scope.pop(node.args.kwarg.arg, None)
        self.receiver_scope_stack.append(scope)
        try:
            self.generic_visit(node)
        finally:
            self.receiver_scope_stack.pop()
        return node

    def visit_ClassDef(self, node):
        if node.name in self.rename_map:
            node.name = self.rename_map[node.name]
        self.generic_visit(node)
        return node

    def visit_ExceptHandler(self, node):
        self.generic_visit(node)
        if node.name and node.name in self.rename_map:
            node.name = self.rename_map[node.name]
        return node

    def visit_Global(self, node):
        node.names = [self.rename_map.get(n, n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self.rename_map.get(n, n) for n in node.names]
        return node


class ParamRenamer(ast.NodeTransformer):
    """
    Second, separate pass (run AFTER IdentifierRenamer above) that
    renames function/method parameter names. Kept as its own pass
    with its own per-function-scope rename maps, deliberately NOT
    folded into IdentifierRenamer's single file-wide rename_map: two
    unrelated functions can each declare a parameter with the same
    name (`def f(url): ...` and `def g(url): ...` are completely
    independent locals), so renaming both through one shared
    name->new_name dict would either force them to the same new name
    (harmless here, since real Python scoping keeps them separate
    regardless) or - more importantly - make it impossible to apply
    the per-function keyword-safety exclusion correctly if a name is
    safe to rename as f's parameter but unsafe as g's (g is called
    with that keyword somewhere, f never is).

    `unsafe_names` is the file-wide set of every name seen as a
    keyword argument in any Call (see _collect_keyword_call_names) -
    a parameter whose name is in this set is left untouched, in
    every function that has one, because this AST-only pass can't
    prove which function a given keyword call site is actually
    targeting.

    `name_fn` is the collision-avoiding name generator to use for new
    parameter names - _rand_name (ASCII, default) or _rand_name_cjk,
    matching whatever rename_identifiers() used for the first pass so
    a single build never mixes both naming styles.
    """
    def __init__(self, unsafe_names: set, name_fn=_rand_name):
        self.unsafe_names = unsafe_names
        self.name_fn = name_fn

    def _rename_params(self, node):
        a = node.args
        # *args/**kwargs slot names themselves are never renamed (see
        # module docstring) - only posonlyargs/args/kwonlyargs.
        param_nodes = list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)
        eligible = [
            p for p in param_nodes
            if p.arg not in self.unsafe_names
            and p.arg not in RESERVED
            and not _is_dunder(p.arg)
        ]
        if not eligible:
            self.generic_visit(node)
            return node

        local_map = {}
        used = {p.arg for p in param_nodes}
        if a.vararg:
            used.add(a.vararg.arg)
        if a.kwarg:
            used.add(a.kwarg.arg)
        for p in eligible:
            new_name = self.name_fn(used)
            used.add(new_name)
            local_map[p.arg] = new_name
            p.arg = new_name

        # Rename every reference to a renamed parameter within this
        # function's own body (and nested bodies, e.g. an inner
        # closure reading the outer parameter) - but NOT into nested
        # FunctionDef/AsyncFunctionDef/Lambda param lists themselves,
        # since a nested function's own same-named parameter would be
        # an independent local that shadows the outer one, not a
        # reference to it. We still walk INTO nested function bodies
        # for Name references (closures legitimately read outer
        # params), just not their own arg lists - generic_visit
        # combined with this same visitor recursing naturally handles
        # that: nested defs get their own _rename_params call (with
        # their own local_map) when this transformer reaches them.
        body_renamer = _ParamBodyRenamer(local_map)
        if isinstance(node, ast.Lambda):
            # Lambda.body is a single expression, not a list of
            # statements like FunctionDef/AsyncFunctionDef.body.
            node.body = body_renamer.visit(node.body)
        else:
            for stmt in node.body:
                body_renamer.visit(stmt)
        for default in list(a.defaults) + list(a.kw_defaults):
            if default is not None:
                body_renamer.visit(default)

        self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node):
        return self._rename_params(node)

    def visit_AsyncFunctionDef(self, node):
        return self._rename_params(node)

    def visit_Lambda(self, node):
        return self._rename_params(node)


class _ParamBodyRenamer(ast.NodeTransformer):
    """Rewrites Name loads/stores matching one function's own
    parameter rename_map, throughout its body. Stops descending into
    a nested function/lambda's OWN parameter list (that's a separate
    scope, handled by ParamRenamer visiting it independently) but
    still rewrites Name references inside nested bodies, since a
    closure can legitimately read an outer parameter by name."""
    def __init__(self, local_map: dict):
        self.local_map = local_map

    def visit_Name(self, node):
        if node.id in self.local_map:
            node.id = self.local_map[node.id]
        return node

    def visit_arg(self, node):
        # A nested function/lambda's own arg nodes are a different
        # scope's parameters - never touched by an outer function's
        # local_map, even if the name happens to match by coincidence
        # (that would be intentional shadowing, not a reference).
        return node


def rename_identifiers(source: str, use_cjk: bool = False, preserve_names=None) -> str:
    """
    use_cjk: when True, every generated name (local variables,
    function/class names, and - via the second pass below -
    parameter names) is a random CJK (Han) identifier instead of the
    default ASCII "_abc123"-style name. See unicode_names.py's module
    docstring for the rationale and the Cython caveat. Purely
    cosmetic to this function's own logic - every collision-avoidance/
    safety rule above (dunders, keyword-arg exclusion, __all__,
    string-literal collisions, etc.) applies identically either way;
    only the SHAPE of the generated names changes.
    """
    name_fn = _rand_name_cjk if use_cjk else _rand_name
    preserve_names = set(preserve_names or ())

    tree = ast.parse(source)

    string_lits = _collect_string_literals(tree)
    public_names = _collect_dunder_all_names(tree)

    def_candidates = _collect_def_names(tree, string_lits, public_names) - preserve_names
    # A definition can be intentionally excluded from def_candidates (for
    # example, ``status`` when the source also contains ``"status"`` for
    # getattr/dispatch/introspection).  It must STILL be excluded from local
    # Store-name candidates.  Otherwise a local variable with the same spelling
    # can place that name in rename_map, causing visit_FunctionDef to rename
    # the method definition while visit_Attribute correctly refuses to rename
    # references to it.  Keep every declared def/class spelling out of the
    # variable map, regardless of whether that definition is eligible.
    all_definition_names = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    var_candidates = (
        _collect_store_names(tree)
        - all_definition_names
        - preserve_names
    )

    used = set(def_candidates) | set(var_candidates)
    rename_map = {}
    for name in def_candidates | var_candidates:
        new_name = name_fn(used)
        used.add(new_name)
        rename_map[name] = new_name

    # attr_rename_map: restricted to def/class names ONLY (see
    # IdentifierRenamer's docstring for why local variable names must
    # never be eligible for attribute-access rewriting).
    attr_rename_map = {name: rename_map[name] for name in def_candidates}

    class_methods_by_node, class_methods_by_name, class_method_nodes = _collect_class_method_info(tree)
    module_scanner = _LocalInstanceReceiverScanner(None, class_methods_by_name)
    for statement in tree.body:
        module_scanner.visit(statement)
    module_instance_receivers = module_scanner.proven_receivers(set())

    transformer = IdentifierRenamer(
        rename_map,
        attr_rename_map,
        class_methods_by_node=class_methods_by_node,
        class_methods_by_name=class_methods_by_name,
        class_method_nodes=class_method_nodes,
        module_instance_receivers=module_instance_receivers,
    )
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)

    # Second pass: parameter renaming. Run against the ALREADY-renamed
    # tree (not the original) so unsafe_names is computed from the
    # same names that will actually appear at each call site - a
    # keyword argument name is never itself a def/class/local-variable
    # name IdentifierRenamer would have touched (Python keyword-arg
    # names in a Call aren't Name/Store nodes), so this ordering has
    # no interaction with the first pass beyond running after it.
    unsafe_names = _collect_keyword_call_names(new_tree) | preserve_names
    param_transformer = ParamRenamer(unsafe_names, name_fn=name_fn)
    final_tree = param_transformer.visit(new_tree)
    ast.fix_missing_locations(final_tree)

    return ast.unparse(final_tree)
