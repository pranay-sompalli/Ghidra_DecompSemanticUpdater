"""
ghidra_decompiler.type_utils
-----------------------------
Utilities for resolving and inspecting Ghidra DataType objects from C type strings.

Public API
----------
    resolve_type(type_str, program)  -> DataType | None
    is_array_type(dt)                -> bool
    is_pointer_type(dt)              -> bool
"""


def resolve_type(type_str, program):
    """
    Robustly convert a C type string into a Ghidra DataType.
    Handles pointers recursively and maps base types locally to avoid
    problematic Java constructor overloads.
    """
    if not type_str:
        return None

    import re
    ts = type_str.strip()

    # 1. Handle pointers recursively (e.g., "char **" -> Pointer(Pointer(Char)))
    if ts.endswith("*"):
        base_str = ts[:-1].strip()
        base_type = resolve_type(base_str, program)
        if base_type:
            from ghidra.program.model.data import PointerDataType
            return PointerDataType(base_type)
        return None

    # Strip prefixes 'struct ', 'union ', 'enum '
    ts_clean = re.sub(r'^(struct|union|enum)\s+', '', ts).strip()

    # 2. Base type mapping using cleaned string
    ts_lower = ts_clean.lower().replace(" ", "")  # "unsigned int" -> "unsignedint"

    from ghidra.program.model.data import (
        IntegerDataType, UnsignedIntegerDataType,
        LongDataType, UnsignedLongDataType,
        LongLongDataType, UnsignedLongLongDataType,
        ShortDataType, UnsignedShortDataType,
        CharDataType, UnsignedCharDataType,
        FloatDataType, DoubleDataType,
        VoidDataType
    )

    try:
        pointer_size = program.getDataTypeManager().getDataOrganization().getPointerSize()
    except Exception:
        pointer_size = 8

    if pointer_size == 8:
        long_t = LongLongDataType()
        ulong_t = UnsignedLongLongDataType()
    else:
        long_t = LongDataType()
        ulong_t = UnsignedLongDataType()

    _base_map = {
        "int":           IntegerDataType(),
        "uint":          UnsignedIntegerDataType(),
        "unsignedint":   UnsignedIntegerDataType(),
        "long":          long_t,
        "ulong":         ulong_t,
        "unsignedlong":  ulong_t,
        "short":         ShortDataType(),
        "ushort":        UnsignedShortDataType(),
        "unsignedshort": UnsignedShortDataType(),
        "char":          CharDataType(),
        "uchar":         UnsignedCharDataType(),
        "unsignedchar":  UnsignedCharDataType(),
        "float":         FloatDataType(),
        "double":        DoubleDataType(),
        "void":          VoidDataType(),
        # size_t will be resolved via DTM lookup in step 3
        "undefined4":    IntegerDataType(),
    }

    dt = _base_map.get(ts_lower)
    if dt:
        return dt

    # 3. Fallback: Check Program's DataTypeManager for custom types/structs/size_t
    try:
        dtm = program.getDataTypeManager()
        # Try common strings first
        found = dtm.getDataType("/" + ts_clean) or dtm.getDataType(ts_clean)
        if found:
            return found

        # Try common paths
        for path in ["/Recovered_Types/", "/BuiltInTypes/", "/generic_clib/"]:
            found = dtm.getDataType(path + ts_clean)
            if found:
                return found
    except Exception:
        pass

    print("[resolve_type] WARNING: could not resolve type '{}'".format(type_str))
    return None


def parse_array_type(type_str, program):
    """
    Parse array types like 'char[8]' or 'int[10]' into a Ghidra ArrayDataType.
    """
    if not type_str:
        return None
    import re
    match = re.match(r'^(.+?)\s*\[\s*(\d+)\s*\]$', type_str.strip())
    if match:
        elem_type_str = match.group(1)
        num_elements = int(match.group(2))
        elem_type = resolve_type(elem_type_str, program)
        if elem_type and num_elements > 0:
            from ghidra.program.model.data import ArrayDataType
            return ArrayDataType(elem_type, num_elements, elem_type.getLength())
    return None


def is_array_type(dt):
    """
    Check if a DataType is an array, resolving through typedefs and using
    fallback name/class checks for robustness in Jython.
    """
    from ghidra.program.model.data import Array
    if not dt:
        return False

    # Resolve through typedefs
    temp = dt
    for _ in range(5):  # limit recursion
        if hasattr(temp, "getDataType") and temp.getDataType() is not None:
            temp = temp.getDataType()
        else:
            break

    if isinstance(temp, Array):
        return True

    # Fallback checks
    name = str(dt.getName())
    if "[" in name and "]" in name:
        return True

    cls_name = dt.getClass().getName()
    if "Array" in cls_name:
        return True

    return False


def is_pointer_type(dt):
    """
    Check if a DataType is a pointer, resolving through typedefs and using
    fallback name/class checks for robustness in Jython.
    """
    from ghidra.program.model.data import Pointer
    if not dt:
        return False

    # Resolve through typedefs
    temp = dt
    for _ in range(5):  # limit recursion
        if hasattr(temp, "getDataType") and temp.getDataType() is not None:
            temp = temp.getDataType()
        else:
            break

    if isinstance(temp, Pointer):
        return True

    cls_name = dt.getClass().getName()
    if "Pointer" in cls_name:
        return True

    return False
