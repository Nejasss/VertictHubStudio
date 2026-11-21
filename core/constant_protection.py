"""Conservative runtime reconstruction for immutable Python constants.

This is an obfuscation pass, not cryptographic protection: values must be
reconstructed in-process and a determined analyst can recover them.  The pass
focuses on integer, float, complex, bytes, bool, None, and tuples composed only
of supported immutable literals.  Plain strings remain handled by
``string_enc``.

Safety rules:
- constants inside structural-pattern matching are left untouched;
- operands of ``is`` / ``is not`` comparisons are left untouched;
- non-literal / mutable tuple expressions are left untouched;
- the feature is opt-in and the caller receives a report of what was changed.

The generated runtime helper is injected before identifier renaming and string
literal encryption, so its helper names are randomized by the existing pass
and its embedded text/data strings are covered by the existing string pass.
"""
from __future__ import annotations

import ast
import hashlib
import json
import secrets
import string
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ConstantProtectionReport:
    transformed_count: int
    transformed_by_type: dict[str, int]
    skipped_by_reason: dict[str, int]
    helper_name: str | None
    gate_key_mixing: bool


@dataclass(frozen=True)
class ConstantInventory:
    counts_by_type: dict[str, int]
    total_supported_literals: int


def _random_identifier(existing: set[str], length: int = 12) -> str:
    alphabet = string.ascii_lowercase
    while True:
        candidate = "_" + "".join(secrets.choice(alphabet) for _ in range(length + 3))
        if candidate not in existing:
            existing.add(candidate)
            return candidate


def _encode_value(value: Any) -> list[Any] | None:
    """Return a JSON-safe tagged representation for supported immutable values."""
    if value is None:
        return ["none", None]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        return ["float", value.hex()]
    if isinstance(value, complex):
        return ["complex", [value.real.hex(), value.imag.hex()]]
    if isinstance(value, bytes):
        return ["bytes", value.hex()]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, tuple):
        encoded = [_encode_value(item) for item in value]
        if any(item is None for item in encoded):
            return None
        return ["tuple", encoded]
    return None


def _is_constant_tuple(node: ast.AST) -> bool:
    if not isinstance(node, ast.Tuple) or not isinstance(node.ctx, ast.Load):
        return False
    try:
        return _encode_value(ast.literal_eval(node)) is not None
    except (ValueError, TypeError, SyntaxError):
        return False


def _mark_subtree(node: ast.AST, marked: set[int]) -> None:
    for child in ast.walk(node):
        marked.add(id(child))


def _collect_unsafe_nodes(tree: ast.AST) -> tuple[set[int], set[int], set[int]]:
    """Return node IDs excluded for patterns, identity, and public ``__all__``."""
    pattern_nodes: set[int] = set()
    identity_nodes: set[int] = set()
    public_api_nodes: set[int] = set()
    pattern_base = getattr(ast, "pattern", None)
    for node in ast.walk(tree):
        if pattern_base is not None and isinstance(node, pattern_base):
            _mark_subtree(node, pattern_nodes)
        if isinstance(node, ast.Compare) and any(
            isinstance(operator, (ast.Is, ast.IsNot)) for operator in node.ops
        ):
            _mark_subtree(node.left, identity_nodes)
            for comparator in node.comparators:
                _mark_subtree(comparator, identity_nodes)
        if isinstance(node, ast.Assign):
            is_all = any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
            if is_all:
                _mark_subtree(node.value, public_api_nodes)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "__all__":
            if node.value is not None:
                _mark_subtree(node.value, public_api_nodes)
    return pattern_nodes, identity_nodes, public_api_nodes


class _ConstantTransformer(ast.NodeTransformer):
    def __init__(
        self,
        helper_name: str,
        pattern_nodes: set[int],
        identity_nodes: set[int],
        public_api_nodes: set[int],
    ):
        self.helper_name = helper_name
        self.pattern_nodes = pattern_nodes
        self.identity_nodes = identity_nodes
        self.public_api_nodes = public_api_nodes
        self.records: list[list[Any]] = []
        self.record_indexes: dict[str, int] = {}
        self.transformed_by_type: dict[str, int] = {}
        self.skipped_by_reason: dict[str, int] = {}

    @staticmethod
    def _type_name(value: Any) -> str:
        if value is None:
            return "none"
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "float"
        if isinstance(value, complex):
            return "complex"
        if isinstance(value, bytes):
            return "bytes"
        if isinstance(value, tuple):
            return "tuple"
        if isinstance(value, str):
            return "string"
        return type(value).__name__

    def _replace(self, node: ast.AST, value: Any) -> ast.Call | None:
        encoded = _encode_value(value)
        if encoded is None:
            self.skipped_by_reason["unsupported-value"] = self.skipped_by_reason.get("unsupported-value", 0) + 1
            return None
        serialized = json.dumps(encoded, ensure_ascii=True, separators=(",", ":"))
        index = self.record_indexes.get(serialized)
        if index is None:
            index = len(self.records)
            self.record_indexes[serialized] = index
            self.records.append(encoded)
        type_name = self._type_name(value)
        self.transformed_by_type[type_name] = self.transformed_by_type.get(type_name, 0) + 1
        call = ast.Call(
            func=ast.Name(id=self.helper_name, ctx=ast.Load()),
            args=[ast.Constant(value=index)],
            keywords=[],
        )
        return ast.copy_location(call, node)

    def visit_Constant(self, node: ast.Constant):
        if id(node) in self.pattern_nodes:
            self.skipped_by_reason["pattern-matching"] = self.skipped_by_reason.get("pattern-matching", 0) + 1
            return node
        if id(node) in self.identity_nodes:
            self.skipped_by_reason["identity-comparison"] = self.skipped_by_reason.get("identity-comparison", 0) + 1
            return node
        if isinstance(node.value, str) or node.value is Ellipsis:
            return node
        if not isinstance(node.value, (bool, int, float, complex, bytes, type(None))):
            return node
        replacement = self._replace(node, node.value)
        return replacement if replacement is not None else node

    def visit_Tuple(self, node: ast.Tuple):
        if id(node) in self.public_api_nodes:
            self.skipped_by_reason["public-api-tuple"] = self.skipped_by_reason.get("public-api-tuple", 0) + 1
            return node
        if id(node) in self.pattern_nodes:
            self.skipped_by_reason["pattern-matching"] = self.skipped_by_reason.get("pattern-matching", 0) + 1
            return node
        if id(node) in self.identity_nodes:
            self.skipped_by_reason["identity-comparison"] = self.skipped_by_reason.get("identity-comparison", 0) + 1
            return node
        if _is_constant_tuple(node):
            try:
                value = ast.literal_eval(node)
            except (ValueError, TypeError, SyntaxError):
                return self.generic_visit(node)
            replacement = self._replace(node, value)
            return replacement if replacement is not None else self.generic_visit(node)
        return self.generic_visit(node)


def _build_runtime_header(
    records: list[list[Any]],
    key: bytes,
    helper_name: str,
    *,
    gate_env_name: str | None,
    gate_token: str | None,
    gate_token_cache_var: str | None,
    used_names: set[str],
) -> tuple[str, bool]:
    json_alias = _random_identifier(used_names)
    os_alias = _random_identifier(used_names)
    hashlib_alias = _random_identifier(used_names)
    sys_alias = _random_identifier(used_names) if (gate_env_name and gate_token) else None
    data_name = _random_identifier(used_names)
    stored_key_name = _random_identifier(used_names)
    env_name_var = _random_identifier(used_names)
    masked_flag_name = _random_identifier(used_names)

    gate_key_mixing = bool(gate_env_name and gate_token)
    stored_key = key
    if gate_key_mixing:
        mask = hashlib.sha256(gate_token.encode("utf-8")).digest()
        stored_key = bytes(value ^ mask[index % len(mask)] for index, value in enumerate(key))

    encrypted_records: list[str] = []
    for record in records:
        plain = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        cipher = bytes(value ^ key[index % len(key)] for index, value in enumerate(plain))
        encrypted_records.append(cipher.hex())

    local_names = {
        name: _random_identifier(used_names)
        for name in (
            "index_arg", "cache_arg", "stored_key", "token", "mask", "key",
            "cipher", "plain", "item", "decode_fn", "entry_arg", "tag",
            "payload", "part", "value",
        )
    }
    ix = local_names
    lines = [
        f"import json as {json_alias}",
        f"import os as {os_alias}",
        f"import hashlib as {hashlib_alias}",
        *([f"import sys as {sys_alias}"] if sys_alias else []),
        f"{data_name} = {tuple(encrypted_records)!r}",
        f"{stored_key_name} = {stored_key.hex()!r}",
        f"{env_name_var} = {gate_env_name!r}",
        f"{masked_flag_name} = {bool(gate_key_mixing)!r}",
        f"def {helper_name}({ix['index_arg']}, {ix['cache_arg']}={{}}):",
        f"    if {ix['index_arg']} in {ix['cache_arg']}:",
        f"        return {ix['cache_arg']}[{ix['index_arg']}]",
        f"    {ix['stored_key']} = bytes.fromhex({stored_key_name})",
        f"    if {masked_flag_name}:",
        (
            f"        {ix['token']} = getattr({sys_alias}, {gate_token_cache_var!r}, None) or "
            f"{os_alias}.environ.get({env_name_var}, '')"
            if sys_alias and gate_token_cache_var
            else f"        {ix['token']} = {os_alias}.environ.get({env_name_var}, '')"
        ),
        f"        if not {ix['token']}:",
        "            raise RuntimeError('constant protection gate token missing')",
        f"        {ix['mask']} = {hashlib_alias}.sha256({ix['token']}.encode('utf-8')).digest()",
        f"        {ix['key']} = bytes(value ^ {ix['mask']}[index % len({ix['mask']})] for index, value in enumerate({ix['stored_key']}))",
        "    else:",
        f"        {ix['key']} = {ix['stored_key']}",
        f"    {ix['cipher']} = bytes.fromhex({data_name}[{ix['index_arg']}])",
        f"    {ix['plain']} = bytes(value ^ {ix['key']}[index % len({ix['key']})] for index, value in enumerate({ix['cipher']}))",
        f"    {ix['item']} = {json_alias}.loads({ix['plain']}.decode('utf-8'))",
        f"    def {ix['decode_fn']}({ix['entry_arg']}):",
        f"        {ix['tag']}, {ix['payload']} = {ix['entry_arg']}",
        f"        if {ix['tag']} == 'none':",
        "            return None",
        f"        if {ix['tag']} == 'bool':",
        f"            return bool({ix['payload']})",
        f"        if {ix['tag']} == 'int':",
        f"            return int({ix['payload']})",
        f"        if {ix['tag']} == 'float':",
        f"            return float.fromhex({ix['payload']})",
        f"        if {ix['tag']} == 'complex':",
        f"            return complex(float.fromhex({ix['payload']}[0]), float.fromhex({ix['payload']}[1]))",
        f"        if {ix['tag']} == 'bytes':",
        f"            return bytes.fromhex({ix['payload']})",
        f"        if {ix['tag']} == 'str':",
        f"            return {ix['payload']}",
        f"        if {ix['tag']} == 'tuple':",
        f"            return tuple({ix['decode_fn']}({ix['part']}) for {ix['part']} in {ix['payload']})",
        "        raise ValueError('unknown constant protection record')",
        f"    {ix['value']} = {ix['decode_fn']}({ix['item']})",
        f"    {ix['cache_arg']}[{ix['index_arg']}] = {ix['value']}",
        f"    return {ix['value']}",
    ]
    return "\n".join(lines) + "\n", gate_key_mixing


def protect_constants(
    source: str,
    *,
    gate_info: dict | None = None,
    gate_token_cache_var: str | None = None,
) -> tuple[str, str, ConstantProtectionReport]:
    """Transform supported immutable literal constants and return source/header/report.

    ``gate_info`` may contain the same per-build ``env_name`` and ``token`` used
    by the existing launcher gate. When present, the constant-table key is
    masked with SHA-256(token); otherwise the feature still works but the key is
    stored in the generated source and offers only casual static concealment.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        raise

    used_names = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    used_names.update(
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    helper_name = _random_identifier(used_names)
    pattern_nodes, identity_nodes, public_api_nodes = _collect_unsafe_nodes(tree)
    transformer = _ConstantTransformer(
        helper_name, pattern_nodes, identity_nodes, public_api_nodes
    )
    transformed_tree = transformer.visit(tree)
    ast.fix_missing_locations(transformed_tree)
    transformed_source = ast.unparse(transformed_tree) + "\n"

    if not transformer.records:
        report = ConstantProtectionReport(
            transformed_count=0,
            transformed_by_type={},
            skipped_by_reason=dict(transformer.skipped_by_reason),
            helper_name=None,
            gate_key_mixing=False,
        )
        return source, "", report

    key = secrets.token_bytes(32)
    gate_info = gate_info or {}
    runtime_header, gate_key_mixing = _build_runtime_header(
        transformer.records,
        key,
        helper_name,
        gate_env_name=gate_info.get("env_name"),
        gate_token=gate_info.get("token"),
        gate_token_cache_var=gate_token_cache_var,
        used_names=used_names,
    )
    report = ConstantProtectionReport(
        transformed_count=sum(transformer.transformed_by_type.values()),
        transformed_by_type=dict(sorted(transformer.transformed_by_type.items())),
        skipped_by_reason=dict(sorted(transformer.skipped_by_reason.items())),
        helper_name=helper_name,
        gate_key_mixing=gate_key_mixing,
    )
    return transformed_source, runtime_header, report


def scan_constants(source: str) -> ConstantInventory:
    """Return a non-executing inventory of literal constants in source."""
    tree = ast.parse(source)
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, str):
                name = "string"
            elif isinstance(value, bool):
                name = "bool"
            elif isinstance(value, int):
                name = "integer"
            elif isinstance(value, float):
                name = "float"
            elif isinstance(value, complex):
                name = "complex"
            elif isinstance(value, bytes):
                name = "bytes"
            elif value is None:
                name = "none"
            elif value is Ellipsis:
                name = "ellipsis"
            else:
                name = type(value).__name__
            counts[name] = counts.get(name, 0) + 1
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and _is_constant_tuple(node):
            counts["tuple"] = counts.get("tuple", 0) + 1
    return ConstantInventory(
        counts_by_type=dict(sorted(counts.items())),
        total_supported_literals=sum(
            count for name, count in counts.items()
            if name in {"integer", "float", "complex", "bytes", "bool", "none", "tuple"}
        ),
    )
