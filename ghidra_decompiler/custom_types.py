'''Utility functions for handling custom struct/enum types and name deduplication.

This module centralises logic that was previously duplicated across several files:
- Sanitising raw ``custom_types`` payloads from the LLM.
- Registering those types with Ghidra's DataTypeManager.
- Ensuring unique variable names within a function (avoiding DuplicateNameException).

The functions are deliberately lightweight and have no external side‑effects beyond the Ghidra program
object passed to them.
'''

from __future__ import annotations

import re
from typing import List, Dict, Set, Any
from ghidra_decompiler.type_utils import resolve_type, parse_array_type


# ---------------------------------------------------------------------------
# Sanitisation helpers
# ---------------------------------------------------------------------------

# Regex that matches Ghidra's internally-generated sub-register field name pattern, e.g. _50_2_, _52_8_.
# These must never appear as struct field names from the LLM.
_GHIDRA_INTERNAL_FIELD_RE = re.compile(r'^_\d+_\d+_$')


def _sanitize_struct_fields(fields: Any) -> List[Dict[str, Any]]:
    """Return a list of well‑formed field dictionaries.

    Each field must contain ``offset`` (int), ``name`` (str) and ``type_str`` (str).
    Invalid entries are ignored.  Fields whose name matches Ghidra's internal
    sub-register naming pattern (e.g. ``_50_2_``) are silently dropped.
    """
    sanitized: List[Dict[str, Any]] = []
    if isinstance(fields, list):
        for f in fields:
            if isinstance(f, dict) and "offset" in f and "name" in f:
                type_str = f.get("type_str") or f.get("type")
                f_name = str(f["name"])
                if type_str:
                    # Reject Ghidra-internal sub-register field names
                    if _GHIDRA_INTERNAL_FIELD_RE.match(f_name):
                        continue
                    try:
                        sanitized.append(
                            {
                                "offset": int(f["offset"]),
                                "name": f_name,
                                "type_str": str(type_str),
                            }
                        )
                    except (ValueError, TypeError):
                        continue
    return sanitized


def _sanitize_enum_values(values: Any) -> List[Dict[str, Any]]:
    """Return a list of well‑formed enum value dictionaries.

    Each entry must contain ``name`` (str) and ``value`` (int).
    """
    sanitized: List[Dict[str, Any]] = []
    if isinstance(values, list):
        for v in values:
            if isinstance(v, dict) and "name" in v:
                val = v.get("value") or v.get("offset")
                if val is not None:
                    try:
                        sanitized.append({"name": str(v["name"]), "value": int(val)})
                    except (ValueError, TypeError):
                        continue
    return sanitized


def sanitize_custom_types(raw: Any) -> List[Dict[str, Any]]:
    """Validate and normalise the ``custom_types`` payload from the LLM.

    The function accepts any JSON‑serialisable object and returns a list of
    dictionaries that conform to the expected schema:

    ``{"type": "struct"|"union"|"enum", "name": str, "fields": [...], "values": [...]}``
    """
    if not isinstance(raw, list):
        return []
    sanitized: List[Dict[str, Any]] = []
    for ct in raw:
        if not (isinstance(ct, dict) and "type" in ct and "name" in ct):
            continue
        ct_type = ct["type"]
        name = ct["name"]
        if ct_type in ("struct", "union"):
            raw_fields = ct.get("fields") or ct.get("members") or []
            fields = _sanitize_struct_fields(raw_fields)
            sanitized.append({"type": ct_type, "name": name, "fields": fields})
        elif ct_type == "enum":
            raw_values = ct.get("values") or ct.get("members") or []
            values = _sanitize_enum_values(raw_values)
            sanitized.append({"type": "enum", "name": name, "values": values})
    return sanitized

# ---------------------------------------------------------------------------
# Name deduplication helper
# ---------------------------------------------------------------------------

def ensure_unique_name(proposed: str, used_names: Set[str]) -> str:
    """Return a name that does not clash with ``used_names``.

    If ``proposed`` is already present, a numeric suffix is appended (e.g.
    ``var`` → ``var_2`` → ``var_3``) until a free name is found.
    """
    if proposed not in used_names:
        return proposed
    suffix = 2
    while f"{proposed}_{suffix}" in used_names:
        suffix += 1
    return f"{proposed}_{suffix}"

# ---------------------------------------------------------------------------
# Ghidra custom datatype registration
# ---------------------------------------------------------------------------

def register_custom_datatypes(program, custom_types: List[Dict[str, Any]]):
    """Register custom ``struct``, ``union`` and ``enum`` types in Ghidra's DataTypeManager.
    """
    if not custom_types:
        return

    from ghidra.program.model.data import (
        StructureDataType,
        UnionDataType,
        EnumDataType,
        CategoryPath,
        PointerDataType,
        Undefined4DataType,
        Undefined1DataType,
    )

    dtm = program.getDataTypeManager()
    category = CategoryPath("/Recovered_Types")
    pointer_size = dtm.getDataOrganization().getPointerSize()

    # -------------------------------------------------------------------
    # Pass 1 – create placeholder structs and unions.
    # -------------------------------------------------------------------
    tx_id = program.startTransaction("Register Custom Types Shells")
    shells: Dict[str, Any] = {}
    try:
        for ct in custom_types:
            name = ct.get("name")
            if not name:
                continue
            clean_name = re.sub(r'^(struct|enum|union)\s+', '', name).strip()
            ct_type = ct.get("type")
            if ct_type not in ("struct", "union"):
                continue

            existing = dtm.getDataType(category.getPath() + "/" + clean_name) or dtm.getDataType("/" + clean_name)
            if not existing:
                if ct_type == "struct":
                    # Compute the maximum offset + size required for the struct.
                    max_size = 0
                    for field in ct.get("fields", []):
                        offset = field.get("offset")
                        f_type_str = field.get("type_str")
                        if offset is None or not f_type_str:
                            continue
                        if f_type_str.endswith("*"):
                            f_len = pointer_size
                        else:
                            # Try array type first, then fall back to regular type resolution
                            resolved = parse_array_type(f_type_str, program)
                            if not resolved:
                                resolved = resolve_type(f_type_str, program)
                            f_len = resolved.getLength() if resolved else 4
                        max_size = max(max_size, offset + f_len)
                    if max_size == 0:
                        max_size = 1
                    dt = StructureDataType(category, clean_name, max_size)
                else: # union
                    dt = UnionDataType(category, clean_name)

                added = dtm.addDataType(dt, None)
                shells[clean_name] = added
                print(f"[Custom Types] Registered shell {ct_type} '{clean_name}' with size {max_size}")
            else:
                if ct_type == "struct":
                    max_size = 0
                    for field in ct.get("fields", []):
                        offset = field.get("offset")
                        f_type_str = field.get("type_str")
                        if offset is None or not f_type_str:
                            continue
                        if f_type_str.endswith("*"):
                            f_len = pointer_size
                        else:
                            resolved = parse_array_type(f_type_str, program)
                            if not resolved:
                                resolved = resolve_type(f_type_str, program)
                            f_len = resolved.getLength() if resolved else 4
                        max_size = max(max_size, offset + f_len)
                    if existing.getLength() < max_size:
                        try:
                            existing.growStructure(max_size - existing.getLength())
                            print(f"[Custom Types] Grew existing struct '{clean_name}' to size {max_size}")
                        except Exception as ge:
                            print(f"[Custom Types] growStructure failed, falling back to manual padding: {ge}")
                            try:
                                for _ in range(max_size - existing.getLength()):
                                    existing.add(Undefined1DataType.dataType)
                            except Exception as fe:
                                print(f"[Custom Types] Manual padding failed for '{clean_name}': {fe}")
                shells[clean_name] = existing
    finally:
        program.endTransaction(tx_id, True)

    # -------------------------------------------------------------------
    # Pass 2 – populate fields and enums.
    # -------------------------------------------------------------------
    tx_id = program.startTransaction("Register Custom Types Definitions")
    try:
        for ct in custom_types:
            name = ct.get("name")
            if not name:
                continue
            clean_name = re.sub(r'^(struct|enum|union)\s+', '', name).strip()
            ct_type = ct.get("type")

            if ct_type in ("struct", "union"):
                struct_dt = shells.get(clean_name)
                if not struct_dt:
                    struct_dt = dtm.getDataType(category.getPath() + "/" + clean_name) or dtm.getDataType("/" + clean_name)
                if not struct_dt:
                    continue

                # Guard: if the struct already has well-named fields in the DTM, don't overwrite.
                # A "well-named" field is one that doesn't match Ghidra's internal pattern.
                if ct_type == "struct" and clean_name not in shells:
                    existing_comps = list(struct_dt.getDefinedComponents())
                    well_named = [
                        c for c in existing_comps
                        if c.getFieldName() and not _GHIDRA_INTERNAL_FIELD_RE.match(c.getFieldName())
                    ]
                    if len(well_named) >= 2:
                        print(f"[Custom Types] Skipping re-population of '{clean_name}' — already has {len(well_named)} well-named field(s) in DTM.")
                        dtm.addDataType(struct_dt, None)
                        continue

                if ct_type == "union":
                    # Remove components from union to overwrite cleanly
                    for component_idx in reversed(range(struct_dt.getNumComponents())):
                        struct_dt.delete(component_idx)

                for field in ct.get("fields", []):
                    offset = field.get("offset")
                    f_name = field.get("name")
                    f_type_str = field.get("type_str")
                    if offset is None or not f_name or not f_type_str:
                        continue
                    # Reject Ghidra-internal field names that slipped through sanitization
                    if _GHIDRA_INTERNAL_FIELD_RE.match(f_name):
                        continue
                    # Handle self‑referential pointers.
                    if f_type_str.endswith("*"):
                        base_str = f_type_str[:-1].strip()
                        base_clean = re.sub(r'^(struct|enum|union)\s+', '', base_str).strip()
                        if base_clean == clean_name:
                            field_type = PointerDataType(struct_dt)
                        else:
                            field_type = resolve_type(f_type_str, program)
                    else:
                        # Try array type first, then fall back to regular type resolution
                        field_type = parse_array_type(f_type_str, program)
                        if not field_type:
                            field_type = resolve_type(f_type_str, program)
                    if not field_type:
                        field_type = Undefined4DataType()
                    try:
                        if ct_type == "struct":
                            if offset + field_type.getLength() <= struct_dt.getLength():
                                struct_dt.replaceAtOffset(offset, field_type, field_type.getLength(), f_name, "")
                                print(f"[Custom Types] Added field {clean_name}.{f_name} at offset {offset}")
                            else:
                                print(
                                    f"[Custom Types] Warning: field {clean_name}.{f_name} offset {offset} is beyond struct length {struct_dt.getLength()}"
                                )
                        else: # union
                            struct_dt.add(field_type, field_type.getLength(), f_name, "")
                            print(f"[Custom Types] Added union member {clean_name}.{f_name} of size {field_type.getLength()}")
                    except Exception as fe:
                        print(
                            f"[Custom Types] Warning: field replacement failed for {clean_name}.{f_name}: {fe}"
                        )
                dtm.addDataType(struct_dt, None)

            elif ct_type == "enum":
                enum_dt = EnumDataType(category, clean_name, 4)
                for v in ct.get("values", []):
                    v_name = v.get("name")
                    v_val = v.get("value")
                    if v_name is not None and v_val is not None:
                        try:
                            enum_dt.add(v_name, int(v_val))
                            print(f"[Custom Types] Added enum value {clean_name}.{v_name} = {v_val}")
                        except Exception as ee:
                            print(f"[Custom Types] Warning: enum value addition failed: {ee}")
                dtm.addDataType(enum_dt, None)
                print(f"[Custom Types] Registered enum '{clean_name}'")
    finally:
        program.endTransaction(tx_id, True)
