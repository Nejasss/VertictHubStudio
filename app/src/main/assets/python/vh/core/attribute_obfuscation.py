"""Conservative instance-attribute renaming for single-module applications.

Only statically proven instance fields on simple top-level classes defined in
the same source file are renamed. Inheritance, descriptors, slots, dynamic
reflection, ambiguous object references, and declared public classes are
preserved. This pass is an obfuscation transform, not a security boundary.
"""
from __future__ import annotations

import ast
import secrets
from dataclasses import dataclass, field


_DYNAMIC_CALLS = {"getattr", "setattr", "hasattr", "delattr", "vars", "dir", "eval", "exec", "globals", "locals"}
_DYNAMIC_ATTR_CALLS = {
    "getattr", "setattr", "hasattr", "delattr", "vars", "dir",
    "getmembers", "getmembers_static", "getattr_static", "getmembers_dynamic",
    "__getattribute__", "__setattr__", "__delattr__", "attrgetter", "methodcaller",
}
_DYNAMIC_IMPORTED_CALLS = {
    # Builtins commonly imported under aliases.
    "getattr", "setattr", "hasattr", "delattr", "vars", "dir", "eval", "exec", "globals", "locals",
    # Inspect helpers that can enumerate/read object members.
    "getmembers", "getmembers_static", "getattr_static", "getmembers_dynamic",
    "currentframe", "stack",
    # operator helpers accept attribute names as runtime strings.
    "attrgetter", "methodcaller",
}
_SPECIAL_ATTRIBUTE_HOOKS = {"__getattr__", "__getattribute__", "__setattr__", "__delattr__", "__dir__", "__new__", "__init_subclass__", "__class_getitem__", "__getstate__", "__setstate__", "__reduce__", "__reduce_ex__"}


@dataclass
class AttributeObfuscationReport:
    classes_seen: int = 0
    classes_transformed: int = 0
    attributes_transformed: int = 0
    accesses_transformed: int = 0
    skipped_classes: int = 0
    skipped_dynamic_classes: int = 0
    skipped_inherited_classes: int = 0
    skipped_decorated_classes: int = 0
    skipped_public_classes: int = 0
    skipped_ambiguous_attributes: int = 0
    skipped_string_reflected_attributes: int = 0
    parse_failed: bool = False
    skip_reasons: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str, *, dynamic: bool = False, inherited: bool = False,
             decorated: bool = False, public: bool = False) -> None:
        self.skipped_classes += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1
        self.skipped_dynamic_classes += int(dynamic)
        self.skipped_inherited_classes += int(inherited)
        self.skipped_decorated_classes += int(decorated)
        self.skipped_public_classes += int(public)


@dataclass
class _ClassInfo:
    node: ast.ClassDef
    name: str
    receivers: dict[int, str]
    attributes: set[str]
    mapping: dict[str, str] = field(default_factory=dict)


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        result: list[str] = []
        for element in target.elts:
            result.extend(_target_names(element))
        return result
    return []


def _class_from_value(value: ast.AST | None, known: dict[str, str], class_names: set[str]) -> str | None:
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return value.func.id if value.func.id in class_names else None
    if isinstance(value, ast.Name):
        return known.get(value.id)
    return None


class _ModuleStoreScanner(ast.NodeVisitor):
    """Count module-scope writes, including control-flow blocks but excluding scopes."""
    def __init__(self):
        self.counts: dict[str, int] = {}

    def visit_FunctionDef(self, node):
        return

    def visit_AsyncFunctionDef(self, node):
        return

    def visit_ClassDef(self, node):
        return

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.counts[node.id] = self.counts.get(node.id, 0) + 1


class _FunctionScopeScanner(ast.NodeVisitor):
    """Collect local bindings in one function without descending into nested scopes."""
    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef):
        self.root = root
        self.bound_names: set[str] = set()
        self.write_counts: dict[str, int] = {}
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()
        args = list(root.args.posonlyargs) + list(root.args.args) + list(root.args.kwonlyargs)
        self.parameter_names = {arg.arg for arg in args}
        self.bound_names.update(self.parameter_names)

    def visit_FunctionDef(self, node):
        if node is self.root:
            for statement in node.body:
                self.visit(statement)
        else:
            self.bound_names.add(node.name)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Lambda(self, node):
        return

    def visit_ClassDef(self, node):
        self.bound_names.add(node.name)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound_names.add(node.id)
            self.write_counts[node.id] = self.write_counts.get(node.id, 0) + 1

    def visit_Global(self, node):
        self.global_names.update(node.names)
        self.bound_names.difference_update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocal_names.update(node.names)
        self.bound_names.difference_update(node.names)

    def visit_Import(self, node):
        for alias in node.names:
            self.bound_names.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != "*":
                self.bound_names.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bound_names.add(node.name)
        self.generic_visit(node)


def _collect_module_instances(tree: ast.Module, class_names: set[str]) -> dict[str, str]:
    """Infer single-assignment module-level `obj = LocalClass()` bindings."""
    known: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            inferred = _class_from_value(statement.value, known, class_names)
            for target in statement.targets:
                for name in _target_names(target):
                    if inferred:
                        known[name] = inferred
                    else:
                        known.pop(name, None)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            inferred = _class_from_value(statement.value, known, class_names)
            if inferred is None and isinstance(statement.annotation, ast.Name) and statement.annotation.id in class_names:
                inferred = statement.annotation.id
            if inferred:
                known[statement.target.id] = inferred
            else:
                known.pop(statement.target.id, None)
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                for name in _target_names(target):
                    known.pop(name, None)

    scanner = _ModuleStoreScanner()
    scanner.visit(tree)
    return {name: class_name for name, class_name in known.items() if scanner.counts.get(name, 0) == 1}


def _collect_function_instances(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    class_names: set[str],
    module_instances: dict[str, str],
) -> tuple[dict[str, str], set[str], set[str], set[str]]:
    """Infer directly-created local instances for one function scope."""
    scanner = _FunctionScopeScanner(function)
    scanner.visit(function)
    known = {name: cls for name, cls in module_instances.items() if name not in scanner.bound_names}

    # Parameter annotations are hints, not runtime guarantees. A caller can
    # still pass a duck-typed object with a same-named field, so v1 never uses
    # an argument annotation alone as proof of the concrete instance class.

    for statement in function.body:
        if isinstance(statement, ast.Assign):
            inferred = _class_from_value(statement.value, known, class_names)
            for target in statement.targets:
                for name in _target_names(target):
                    if inferred:
                        known[name] = inferred
                    else:
                        known.pop(name, None)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            inferred = _class_from_value(statement.value, known, class_names)
            if inferred is None and isinstance(statement.annotation, ast.Name) and statement.annotation.id in class_names:
                inferred = statement.annotation.id
            if inferred:
                known[statement.target.id] = inferred
            else:
                known.pop(statement.target.id, None)
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                for name in _target_names(target):
                    known.pop(name, None)

    for name in list(known):
        if name in scanner.global_names or name in scanner.nonlocal_names:
            known.pop(name, None)
        elif name in scanner.parameter_names:
            if scanner.write_counts.get(name, 0):
                known.pop(name, None)
        elif scanner.write_counts.get(name, 0) != 1:
            known.pop(name, None)
    return known, scanner.bound_names, scanner.global_names, scanner.nonlocal_names


def _module_public_names(tree: ast.Module) -> set[str]:
    public: set[str] = set()
    for statement in tree.body:
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(statement, ast.Assign):
            targets, value = statement.targets, statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets, value = [statement.target], statement.value
        if value is None or not any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
            continue
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            for item in value.elts:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    public.add(item.value)
    return public


def _class_body_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for statement in node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(statement.name)
            continue
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                names.update(_target_names(target))
    return names


def _class_skip_reason(node: ast.ClassDef) -> tuple[str | None, str | None]:
    if node.decorator_list:
        return "class decorator may define external attribute semantics", "decorated"
    if node.bases or node.keywords:
        return "inheritance/metaclass semantics are outside v1 scope", "inherited"
    if "__slots__" in _class_body_names(node):
        return "class uses __slots__", "dynamic"
    for child in ast.walk(node):
        if isinstance(child, ast.ClassDef) and child is not node:
            return "nested class", "dynamic"
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if child.name in _SPECIAL_ATTRIBUTE_HOOKS:
                return f"custom attribute hook: {child.name}", "dynamic"
            if child.decorator_list:
                return "decorated methods/properties are outside v1 scope", "decorated"
        if isinstance(child, ast.Attribute) and child.attr in {"__dict__", "__slots__"}:
            return "class introspects __dict__/__slots__", "dynamic"
        if isinstance(child, ast.Name) and child.id in {"__dict__", "__slots__"}:
            return "class introspects __dict__/__slots__", "dynamic"
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id in _DYNAMIC_CALLS:
                return f"dynamic reflection call: {child.func.id}", "dynamic"
            if isinstance(child.func, ast.Attribute) and child.func.attr in _DYNAMIC_ATTR_CALLS:
                return f"dynamic inspection call: {child.func.attr}", "dynamic"
    return None, None


def _receiver_reassigned(method: ast.FunctionDef | ast.AsyncFunctionDef, receiver: str) -> bool:
    for child in ast.walk(method):
        if isinstance(child, ast.Name) and child.id == receiver and isinstance(child.ctx, (ast.Store, ast.Del)):
            return True
        if isinstance(child, (ast.Global, ast.Nonlocal)) and receiver in child.names:
            return True
        if child is not method and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            nested_args = getattr(child, "args", None)
            if nested_args is not None:
                all_args = list(nested_args.posonlyargs) + list(nested_args.args) + list(nested_args.kwonlyargs)
                if any(arg.arg == receiver for arg in all_args):
                    return True
    return False


def _build_class_infos(tree: ast.Module, report: AttributeObfuscationReport) -> dict[int, _ClassInfo]:
    top_level_classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    report.classes_seen = len(top_level_classes)
    public_names = _module_public_names(tree)
    infos: dict[int, _ClassInfo] = {}
    for node in top_level_classes:
        if node.name in public_names:
            report.skip("class is declared in __all__", public=True)
            continue
        reason, kind = _class_skip_reason(node)
        if reason:
            report.skip(reason, dynamic=(kind == "dynamic"), inherited=(kind == "inherited"), decorated=(kind == "decorated"))
            continue
        methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        receivers: dict[int, str] = {}
        attributes: set[str] = set()
        reassigned = False
        for method in methods:
            args = list(method.args.posonlyargs) + list(method.args.args)
            if not args:
                continue
            receiver = args[0].arg
            if _receiver_reassigned(method, receiver):
                reassigned = True
                break
            receivers[id(method)] = receiver
            for child in ast.walk(method):
                if (isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name)
                        and child.value.id == receiver and isinstance(child.ctx, (ast.Store, ast.Del))
                        and not child.attr.startswith("__")):
                    attributes.add(child.attr)
        if reassigned:
            report.skip("instance receiver is rebound or shadowed", dynamic=True)
            continue
        attributes -= _class_body_names(node)
        if attributes:
            infos[id(node)] = _ClassInfo(node=node, name=node.name, receivers=receivers, attributes=attributes)
    return infos


def _parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _containing_class_and_receivers(node: ast.AST, parents: dict[int, ast.AST], infos: dict[int, _ClassInfo]):
    receivers: set[str] = set()
    current = parents.get(id(node))
    owner: _ClassInfo | None = None
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for info in infos.values():
                receiver = info.receivers.get(id(current))
                if receiver:
                    receivers.add(receiver)
        if isinstance(current, ast.ClassDef):
            owner = infos.get(id(current))
            break
        current = parents.get(id(current))
    return owner, receivers


def _resolve_instance_class(
    node: ast.AST,
    name: str,
    parents: dict[int, ast.AST],
    module_instances: dict[str, str],
    function_scopes: dict[int, tuple[dict[str, str], set[str], set[str], set[str]]],
) -> str | None:
    """Resolve a base name through nearest local/nonlocal scopes, then module scope."""
    current = parents.get(id(node))
    nonlocal_pending = False
    while current is not None:
        if isinstance(current, ast.Lambda):
            args = current.args
            lambda_names = {a.arg for a in (list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs))}
            if args.vararg:
                lambda_names.add(args.vararg.arg)
            if args.kwarg:
                lambda_names.add(args.kwarg.arg)
            if name in lambda_names:
                return None
        elif isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            targets = set()
            for generator in current.generators:
                targets.update(n.id for n in ast.walk(generator.target) if isinstance(n, ast.Name))
            if name in targets:
                return None
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bindings, bound_names, global_names, nonlocal_names = function_scopes[id(current)]
            if name in global_names:
                return None
            if name in nonlocal_names:
                nonlocal_pending = True
                current = parents.get(id(current))
                continue
            if name in bound_names:
                return bindings.get(name)
        current = parents.get(id(current))
    return None if nonlocal_pending else module_instances.get(name)


def _global_dynamic_reflection(tree: ast.Module) -> bool:
    """Detect direct, imported, and simply-aliased reflection helpers."""
    dynamic_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if alias.name in _DYNAMIC_IMPORTED_CALLS or bound_name in _DYNAMIC_CALLS:
                    dynamic_names.add(bound_name)

    # Follow a few simple assignment aliases (e.g. lookup = getattr;
    # reader = lookup) without attempting general data-flow analysis.
    for _ in range(3):
        discovered: set[str] = set()
        for node in ast.walk(tree):
            value = None
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                value, targets = node.value, node.targets
            elif isinstance(node, ast.AnnAssign):
                value, targets = node.value, [node.target]
            elif isinstance(node, ast.NamedExpr):
                value, targets = node.value, [node.target]
            if value is None:
                continue
            is_dynamic_value = (
                isinstance(value, ast.Name) and (value.id in _DYNAMIC_CALLS or value.id in dynamic_names)
            ) or (
                isinstance(value, ast.Attribute) and value.attr in _DYNAMIC_ATTR_CALLS
            )
            if is_dynamic_value:
                for target in targets:
                    discovered.update(_target_names(target))
        discovered -= dynamic_names
        if not discovered:
            break
        dynamic_names.update(discovered)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and (
                node.func.id in _DYNAMIC_CALLS or node.func.id in dynamic_names
            ):
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in _DYNAMIC_ATTR_CALLS:
                return True
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            return True
    return False


def _fresh_attribute_name(used: set[str]) -> str:
    while True:
        candidate = "_ao_" + secrets.token_hex(5)
        if candidate not in used:
            used.add(candidate)
            return candidate


class _AttributeTransformer(ast.NodeTransformer):
    def __init__(self, safe_accesses: dict[int, tuple[int, str]], infos: dict[int, _ClassInfo]):
        self.safe_accesses = safe_accesses
        self.infos = infos
        self.accesses = 0

    def visit_Attribute(self, node: ast.Attribute):
        self.generic_visit(node)
        info_and_name = self.safe_accesses.get(id(node))
        if info_and_name is None:
            return node
        info_id, original_name = info_and_name
        info = self.infos[info_id]
        node.attr = info.mapping[original_name]
        self.accesses += 1
        return node


def obfuscate_attributes(source: str) -> tuple[str, AttributeObfuscationReport]:
    """Rename proven local instance fields and preserve uncertain cases."""
    report = AttributeObfuscationReport()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        report.parse_failed = True
        return source, report

    infos = _build_class_infos(tree, report)
    if not infos:
        return source, report

    class_names = {info.name for info in infos.values()}
    module_instances = _collect_module_instances(tree, class_names)
    parents = _parent_map(tree)
    function_scopes: dict[int, tuple[dict[str, str], set[str], set[str], set[str]]] = {}
    for function in ast.walk(tree):
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_scopes[id(function)] = _collect_function_instances(
                function, class_names, module_instances
            )
    candidates_by_name: dict[str, list[_ClassInfo]] = {}
    for info in infos.values():
        for attr in info.attributes:
            candidates_by_name.setdefault(attr, []).append(info)

    ambiguous: set[tuple[int, str]] = set()
    string_literals = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    for attr_name, attr_infos in candidates_by_name.items():
        for info in attr_infos:
            if attr_name in string_literals:
                ambiguous.add((id(info.node), attr_name))
                report.skipped_string_reflected_attributes += 1

    if _global_dynamic_reflection(tree):
        for info in infos.values():
            report.skip("module uses dynamic attribute reflection", dynamic=True)
        return source, report

    safe_accesses: dict[int, tuple[int, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or node.attr not in candidates_by_name:
            continue
        attr_infos = candidates_by_name[node.attr]
        owner, receiver_names = _containing_class_and_receivers(node, parents, infos)
        base_name = node.value.id if isinstance(node.value, ast.Name) else None

        if owner is not None and base_name is not None and base_name in receiver_names and node.attr in owner.attributes:
            safe_accesses[id(node)] = (id(owner.node), node.attr)
            continue

        inferred_class = (
            _resolve_instance_class(node, base_name, parents, module_instances, function_scopes)
            if base_name is not None else None
        )
        if inferred_class:
            matching = [info for info in attr_infos if info.name == inferred_class]
            if len(matching) == 1:
                safe_accesses[id(node)] = (id(matching[0].node), node.attr)
                continue

        # A field access through any other base (unknown parameter, factory
        # return, class object, another class, etc.) is ambiguous. Do not
        # rename that field in any candidate class.
        if owner is not None and base_name is not None and base_name in receiver_names:
            # It is a receiver belonging to this class but not a candidate
            # stored field (e.g. a method/descriptor). Other classes with a
            # same-named candidate are not implicated.
            continue
        for info in attr_infos:
            ambiguous.add((id(info.node), node.attr))

    used_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    used_names.update(node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute))
    used_names.update(node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))

    for info in infos.values():
        safe_attributes = sorted(attr for attr in info.attributes if (id(info.node), attr) not in ambiguous)
        report.skipped_ambiguous_attributes += len(info.attributes) - len(safe_attributes)
        if safe_attributes:
            info.mapping = {attr: _fresh_attribute_name(used_names) for attr in safe_attributes}

    # Remove references to attributes that were deemed ambiguous, even if
    # another class with the same name has a safe mapping.
    safe_accesses = {
        node_id: (info_id, name)
        for node_id, (info_id, name) in safe_accesses.items()
        if name in infos[info_id].mapping
    }
    if not safe_accesses:
        return source, report

    transformer = _AttributeTransformer(safe_accesses, infos)
    transformed = transformer.visit(tree)
    ast.fix_missing_locations(transformed)
    report.classes_transformed = sum(bool(info.mapping) for info in infos.values())
    report.attributes_transformed = sum(len(info.mapping) for info in infos.values())
    report.accesses_transformed = transformer.accesses
    return ast.unparse(transformed), report
