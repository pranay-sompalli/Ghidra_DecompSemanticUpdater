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

    from ghidra.program.model.data import (
        IntegerDataType, UnsignedIntegerDataType,
        LongDataType, UnsignedLongDataType,
        ShortDataType, UnsignedShortDataType,
        CharDataType, UnsignedCharDataType,
        FloatDataType, DoubleDataType,
        VoidDataType, PointerDataType
    )

    ts = type_str.strip()

    # 1. Handle pointers recursively (e.g., "char **" -> Pointer(Pointer(Char)))
    if ts.endswith("*"):
        base_str = ts[:-1].strip()
        base_type = resolve_type(base_str, program)
        if base_type:
            return PointerDataType(base_type)
        return None

    # 2. Base type mapping
    ts_lower = ts.lower().replace(" ", "")  # "unsigned int" -> "unsignedint"

    _base_map = {
        "int":           IntegerDataType(),
        "uint":          UnsignedIntegerDataType(),
        "unsignedint":   UnsignedIntegerDataType(),
        "long":          LongDataType(),
        "ulong":         UnsignedLongDataType(),
        "unsignedlong":  UnsignedLongDataType(),
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
        found = dtm.getDataType("/" + ts) or dtm.getDataType(ts)
        if found:
            return found

        # Try common paths
        for path in ["/BuiltInTypes/", "/generic_clib/"]:
            found = dtm.getDataType(path + ts)
            if found:
                return found
    except Exception:
        pass

    print("[resolve_type] WARNING: could not resolve type '{}'".format(type_str))
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
