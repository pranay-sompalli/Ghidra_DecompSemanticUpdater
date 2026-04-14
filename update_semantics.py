import cerebras_suggestions

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
    ts_lower = ts.lower().replace(" ", "") # "unsigned int" -> "unsignedint"
    
    _base_map = {
        "int":          IntegerDataType(),
        "uint":         UnsignedIntegerDataType(),
        "unsignedint":  UnsignedIntegerDataType(),
        "long":         LongDataType(),
        "ulong":        UnsignedLongDataType(),
        "unsignedlong": UnsignedLongDataType(),
        "short":        ShortDataType(),
        "ushort":       UnsignedShortDataType(),
        "unsignedshort":UnsignedShortDataType(),
        "char":         CharDataType(),
        "uchar":        UnsignedCharDataType(),
        "unsignedchar": UnsignedCharDataType(),
        "float":        FloatDataType(),
        "double":       DoubleDataType(),
        "void":         VoidDataType(),
        # size_t will be resolved via DTM lookup in step 3
        "undefined4":   IntegerDataType(), 
    }
    
    dt = _base_map.get(ts_lower)
    if dt:
        return dt

    # 3. Fallback: Check Program's DataTypeManager for custom types/structs/size_t
    try:
        dtm = program.getDataTypeManager()
        # Try common strings first
        found = dtm.getDataType("/" + ts) or dtm.getDataType(ts)
        if found: return found
        
        # Try common paths
        for path in ["/BuiltInTypes/", "/generic_clib/"]:
            found = dtm.getDataType(path + ts)
            if found: return found
    except:
        pass

    print("[resolve_type] WARNING: could not resolve type '{}'".format(type_str))
    return None


def is_array_type(dt):
    """
    Helper to check if a DataType is an array, resolving through typedefs and 
    using fallback name/class checks for robustness in Jython.
    """
    from ghidra.program.model.data import Array
    if not dt:
        return False
    
    # Resolve through typedefs
    temp = dt
    for _ in range(5): # limit recursion
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
    Helper to check if a DataType is a pointer, resolving through typedefs and 
    using fallback name/class checks for robustness in Jython.
    """
    from ghidra.program.model.data import Pointer
    if not dt:
        return False

    # Resolve through typedefs
    temp = dt
    for _ in range(5): # limit recursion
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


def strip_leading_underscores(program):
    """
    Strip a leading underscore from any function whose name starts with _s or _p.
    Run once after analysis on the whole program.
    """

    txId = program.startTransaction("Strip Leading Underscores")
    try:
        for func in program.getFunctionManager().getFunctions(True):
            name = func.getName()
            if name.startswith("_s") or name.startswith("_p"):
                change_function_name(program, func, name[1:])
    finally:
        program.endTransaction(txId, True)


def update_function_semantics(program, func, name):
    """
    Update the semantics of a function:
      - Detect return type (void vs int) from P-Code RETURN ops.
      - Preserve (or restore) all parameters while changing the return type.
      - For 'main': rename parameters and assign proper types based on count:
          2 params → int main(int argc, char **argv)
          3 params → int main(int argc, char **argv, char **envp)
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp, HighFunctionDBUtil
    from ghidra.program.model.data import (
        IntegerDataType, VoidDataType, CharDataType, PointerDataType
    )
    from ghidra.program.model.listing import ParameterImpl, Function
    from java.util import ArrayList

    # ── Decompile (outside the transaction – read-only) ──────────────────────
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    results = decompiler.decompileFunction(func, 30, None)
    decompiler.dispose()

    suggested_type_name = "void"
    high_func = None

    if results.decompileCompleted():
        high_func = results.getHighFunction()
        if high_func:
            for op in high_func.getPcodeOps():
                if op.getOpcode() == PcodeOp.RETURN:
                    # Input 0 = control/return-address; Input 1+ = actual return value
                    if op.getNumInputs() > 1:
                        suggested_type_name = "int"
                        break
        else:
            print("[{}] {}: WARNING - no HighFunction from decompiler".format(
                func.getEntryPoint(), func.getName()))
    else:
        print("[{}] {}: WARNING - decompile did not complete: {}".format(
            func.getEntryPoint(), func.getName(), results.getErrorMessage()))

    print("[{}] {}: detected return type = {}".format(
        func.getEntryPoint(), func.getName(), suggested_type_name))

    # ── Apply changes in a single transaction ────────────────────────────────
    txId = program.startTransaction("Update Function Semantics: " + name)
    try:
        # Step 0 - rename function to its detected core name
        change_function_name(program, func, name)

        new_type = IntegerDataType() if suggested_type_name == "int" else VoidDataType()

        # Step 1 – update return type.
        func.setReturnType(new_type, SourceType.USER_DEFINED)

        # Step 2 – restore parameters from the decompiler's analysis.
        if high_func is not None:
            HighFunctionDBUtil.commitParamsToDatabase(
                high_func,
                True,                                            # useDataTypes
                HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, # leave return type alone
                SourceType.USER_DEFINED,
            )
            # Step 2.1 - commit local names as well, so HighVariables (iVar1, etc.) 
            # become actual variables in the database.
            HighFunctionDBUtil.commitLocalNamesToDatabase(high_func, SourceType.USER_DEFINED)

        # Step 3 – for 'main', apply canonical names and types.
        if name == "main":
            param_count = func.getParameterCount()
            if param_count in (2, 3):
                char_pp   = PointerDataType(PointerDataType(CharDataType()))
                int_type  = IntegerDataType()

                new_params = ArrayList()
                new_params.add(ParameterImpl("argc", int_type, program))
                new_params.add(ParameterImpl("argv", char_pp, program))
                if param_count == 3:
                    new_params.add(ParameterImpl("envp", char_pp, program))

                change_function_parameters(
                    program, func, new_params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS
                )
                print("[{}] main: applied {}-param signature".format(
                    func.getEntryPoint(), param_count))

        print("[{}] {}: return type set to {}".format(
            func.getEntryPoint(), func.getName(), suggested_type_name))

    except Exception as e:
        import traceback
        print("Error updating {}: {}".format(func.getName(), str(e)))
        traceback.print_exc()
    finally:
        program.endTransaction(txId, True)


def update_variable_names_and_types(program, func, updates):
    """
    Rename and/or retype local variables and parameters within a function.

    Parameters
    ----------
    program : ghidra.program.model.listing.Program
    func    : ghidra.program.model.listing.Function
    updates : list[dict]
        Each dict may contain:
          "name"     (str)             – current variable name to match (required)
          "new_name" (str | None)      – rename to this; omit or None to keep current
          "new_type" (DataType | None) – retype to this; omit or None to keep current

    Returns
    -------
    int : number of variables successfully updated

    Example
    -------
    from ghidra.program.model.data import IntegerDataType, PointerDataType, CharDataType

    update_variable_names_and_types(program, func, [
        {"name": "local_8",  "new_name": "counter", "new_type": IntegerDataType()},
        {"name": "local_10", "new_name": "index"},                          # rename only
        {"name": "param_2",  "new_type": PointerDataType(CharDataType())},  # retype only
    ])
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.data import Array, Pointer

    if not updates:
        return 0

    # Build a name -> variable map covering parameters AND local variables.
    var_map = {}
    for var in func.getAllVariables():
        var_map[var.getName()] = var

    updated_count = 0
    txId = program.startTransaction("Update Variables: " + func.getName())
    try:
        for entry in updates:
            current_name = entry.get("name")
            new_name     = entry.get("new_name")
            new_type     = entry.get("new_type")

            if not current_name:
                print("  [skip] update entry missing 'name' key: {}".format(entry))
                continue

            var = var_map.get(current_name)
            if var is None:
                print("  [skip] variable '{}' not found in {}".format(
                    current_name, func.getName()))
                continue

            try:
                if new_type is not None:
                    existing_type = var.getDataType()
                    # If existing type is an array and new type is a pointer, leave it as array
                    if is_array_type(existing_type) and is_pointer_type(new_type):
                        print("  [{}] Skipping retype of array '{}' ({}) to pointer '{}' ({})".format(
                            func.getName(), current_name, existing_type.getName(), 
                            new_type.getName(), new_type.getClass().getSimpleName()))
                        new_type = None

                if new_type is not None:
                    # align=False preserves stack layout; force=True allows size changes
                    var.setDataType(new_type, False, True, SourceType.USER_DEFINED)

                if new_name is not None and new_name != current_name:
                    var.setName(new_name, SourceType.USER_DEFINED)
                    # Keep the map in sync in case a later entry references the new name
                    var_map.pop(current_name, None)
                    var_map[new_name] = var

                updated_count += 1
                print("  [{}] {}: '{}' -> name='{}' type='{}'".format(
                    func.getEntryPoint(),
                    func.getName(),
                    current_name,
                    new_name  if new_name  is not None else current_name,
                    new_type.getName() if new_type is not None else "(unchanged)",
                ))

            except Exception as var_err:
                import traceback
                print("  [error] could not update '{}': {}".format(
                    current_name, str(var_err)))
                traceback.print_exc()

    except Exception as e:
        import traceback
        print("Error in update_variable_names_and_types for {}: {}".format(
            func.getName(), str(e)))
        traceback.print_exc()
    finally:
        program.endTransaction(txId, True)

    return updated_count


def change_function_name(program, func, new_name):
    """
    Wrapper function to safely change a function's name within a transaction.
    """
    from ghidra.program.model.symbol import SourceType

    txId = program.startTransaction("Rename Function: " + func.getName())
    try:
        old_name = func.getName()
        func.setName(new_name, SourceType.USER_DEFINED)
        print("[{}] Renamed function: '{}' -> '{}'".format(
            func.getEntryPoint(), old_name, new_name))
        return True
    except Exception as e:
        import traceback
        print("Error renaming function {}: {}".format(func.getName(), str(e)))
        traceback.print_exc()
        return False
    finally:
        program.endTransaction(txId, True)


def change_function_parameters(program, func, new_params, update_type=None):
    """
    Wrapper function to completely replace a function's parameters.
    
    Parameters
    ----------
    program    : ghidra.program.model.listing.Program
    func       : ghidra.program.model.listing.Function
    new_params : java.util.List of ghidra.program.model.listing.Parameter
    update_type: optional FunctionUpdateType, defaults to CUSTOM_STORAGE
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.listing import Function

    if update_type is None:
        update_type = Function.FunctionUpdateType.CUSTOM_STORAGE

    txId = program.startTransaction("Update Parameters: " + func.getName())
    try:
        func.replaceParameters(
            new_params,
            update_type,
            True,  # force
            SourceType.USER_DEFINED,
        )
        print("[{}] Successfully updated parameters for '{}'".format(
            func.getEntryPoint(), func.getName()))
        return True
    except BaseException as e:
        print("Error updating parameters for {}: {}".format(func.getName(), str(e)))
        return False
    finally:
        program.endTransaction(txId, True)
        
def _apply_function_name_suggestion(program, func, suggestions):
    import re
    func_name = func.getName()
    new_func_name = suggestions.get("function_name")
    if new_func_name and new_func_name != func_name and func_name != "main":
        # Only change the name if the current name is alphanumerical/auto-generated
        if re.match(r'^(FUN_|SUB_|thunk_)?[0-9a-fA-F]+$', func_name) or any(c.isdigit() for c in func_name):
            change_function_name(program, func, new_func_name)
            return new_func_name
    return func_name

def _apply_variable_suggestions(program, func, func_name, suggestions):
    var_updates = []
    for entry in suggestions.get("variables", []):
        current_name  = entry.get("name")
        new_name      = entry.get("new_name")
        new_type_str  = entry.get("new_type_str")
        new_type      = resolve_type(new_type_str, program) if new_type_str else None

        if (new_name and new_name != current_name) or new_type is not None:
            var_updates.append({
                "name":     current_name,
                "new_name": new_name if new_name != current_name else None,
                "new_type": new_type,
            })

    if var_updates:
        updated = update_variable_names_and_types(program, func, var_updates)
        print("[Cerebras] Applied {} variable update(s) to '{}'".format(
            updated, func_name))
    else:
        print("[Cerebras] No variable suggestions to apply for '{}'".format(func_name))

def _apply_parameter_suggestions(program, func, func_name, suggestions):
    from ghidra.program.model.listing import ParameterImpl, Function
    from java.util import ArrayList
    
    param_suggestions = suggestions.get("parameters", [])
    if func_name == "main":
        print("[Cerebras] Preserving manual parameter signature for 'main'")
        return

    if not param_suggestions:
        print("[Cerebras] No parameter suggestions for '{}'".format(func_name))
        return

    current_params = list(func.getParameters())
    new_params = ArrayList()
    changed = False

    for param in current_params:
        old_name = param.getName()
        suggestion = next((s for s in param_suggestions if s.get("name") == old_name), None)

        if suggestion:
            new_name     = suggestion.get("new_name") or old_name
            new_type_str = suggestion.get("new_type_str")
            new_type     = resolve_type(new_type_str, program) if new_type_str else None
            final_type   = new_type if new_type is not None else param.getDataType()

            new_params.add(ParameterImpl(new_name, final_type, program))
            if new_name != old_name or new_type is not None:
                changed = True
                print("[Cerebras]   param '{}' -> name='{}' type='{}'".format(
                    old_name, new_name, new_type_str if new_type_str else "(unchanged)"))
        else:
            new_params.add(ParameterImpl(old_name, param.getDataType(), program))

    if changed:
        change_function_parameters(program, func, new_params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS)
        print("[Cerebras] Applied parameter updates to '{}'".format(func_name))
    else:
        print("[Cerebras] No parameter changes needed for '{}'".format(func_name))

def apply_cerebras_suggestions(program, func, suggestions):
    """
    Apply variable, parameter, and function name suggestions obtained from the Cerebras AI layer
    to the function in Ghidra.

    Must be called AFTER update_function_semantics() so that commitParamsToDatabase
    has already populated the function's parameter list.

    Parameters
    ----------
    program      : ghidra.program.model.listing.Program
    func         : ghidra.program.model.listing.Function
    suggestions  : dict
        Precomputed dictionary of AI suggestions containing 'variables',
        'parameters', and optionally 'function_name'.
    """
    func_name = _apply_function_name_suggestion(program, func, suggestions)
    _apply_variable_suggestions(program, func, func_name, suggestions)
    _apply_parameter_suggestions(program, func, func_name, suggestions)

def sanitize_c_code(c_code):
    """
    Performs multiple sanitization passes on the C code:
    1. Converts hexadecimal numbers (0x...) to decimal.
    2. Converts boolean literals (true, false) to integers (1, 0).
    
    Skips over string literals to avoid corrupting text.
    """
    import re
    if not c_code:
        return c_code
        
    # Split the C code by C-style string literals (handling escaped quotes).
    # Parts at even indices are code, odd indices are strings.
    parts = re.split(r'("(?:\\.|[^"\\])*")', c_code)
    
    for i in range(0, len(parts), 2):
        # Pass 1: Convert hex (like 0x1A or 0x0) to decimal.
        parts[i] = re.sub(
            r'\b0[xX][0-9a-fA-F]+\b',
            lambda match: str(int(match.group(0), 16)),
            parts[i]
        )
        
        # Pass 2: Convert boolean literals to integers.
        parts[i] = re.sub(r'\btrue\b',  '1', parts[i])
        parts[i] = re.sub(r'\bfalse\b', '0', parts[i])
        
    return "".join(parts)

def is_generic_name(name):
    """Checks if a name matches Ghidra's autogenerated naming scheme."""
    import re
    generic_pattern = r'^(param_\d+|local_[0-9a-fA-F]+|uVar\d+|iVar\d+|sVar\d+|cVar\d+|undefined.*)$'
    return bool(re.match(generic_pattern, name))

def clean_c_argument(arg_str):
    """Strips modifiers like &, *, and casts from C argument strings."""
    import re
    arg_str = re.sub(r'^[\&\*]+', '', arg_str)
    arg_str = re.sub(r'^\([^)]+\)\s*', '', arg_str)
    return re.sub(r'^[\&\*]+', '', arg_str).strip()

def align_usage_with_called_functions(program, caller_func, caller_c_code, core_functions):
    """
    Parses the decompiled C code of a caller function to find calls to core functions.
    Aligns naming usage:
    - If caller passes a meaningful variable name to a callee's generic parameter, renames the callee's parameter.
    - If callee has a meaningful parameter name but caller passes a generic variable, renames the caller's variable.
    """
    import re
    from ghidra.program.model.listing import ParameterImpl, Function
    from java.util import ArrayList
    
    caller_var_updates = []
    caller_vars = {v.getName(): v for v in caller_func.getAllVariables()}
    
    for callee_func in core_functions:
        callee_name = callee_func.getName()
        if callee_name == caller_func.getName():
            continue 
            
        pattern = r'\b' + re.escape(callee_name) + r'\s*\(([^)]*)\)'
        for match in re.finditer(pattern, caller_c_code):
            args = [a.strip() for a in match.group(1).split(',')]
            
            callee_params = list(callee_func.getParameters())
            new_callee_params = ArrayList()
            callee_changed = False
            callee_var_names = {v.getName() for v in callee_func.getAllVariables()}
            
            for i, a in enumerate(args):
                a = clean_c_argument(a)
                
                caller_has_good_name = re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', a) and not is_generic_name(a)
                caller_is_generic = re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', a) and is_generic_name(a)
                
                callee_old_name = callee_params[i].getName() if i < len(callee_params) else None
                callee_has_good_name = callee_old_name and not is_generic_name(callee_old_name)
                callee_is_generic = callee_old_name and is_generic_name(callee_old_name)
                
                if i < len(callee_params):
                    proposed_callee_name = callee_old_name
                    proposed_callee_type = callee_params[i].getDataType()
                    
                    if a in caller_vars:
                        caller_type = caller_vars[a].getDataType()
                        if str(proposed_callee_type) != str(caller_type) and "undefined" not in str(caller_type):
                            proposed_callee_type = caller_type
                            callee_changed = True
                            print("[Alignment] Caller '{}' -> Callee '{}' arg {}: propagating type '{}'".format(
                                caller_func.getName(), callee_name, i, caller_type))
                    
                    if caller_has_good_name and callee_old_name != a:
                        if a in callee_var_names:
                            print("[Alignment] Callee '{}' already has a variable named '{}'. Skipping rename to avoid collision.".format(
                                callee_name, a))
                        else:
                            proposed_callee_name = a
                            print("[Alignment] Caller '{}' -> Callee '{}' arg {}: renaming param '{}' -> '{}'".format(
                                caller_func.getName(), callee_name, i, callee_old_name, a))
                            callee_changed = True
                            callee_var_names.add(a)
                    
                    elif callee_has_good_name and caller_is_generic:
                        callee_type = callee_params[i].getDataType()
                        
                        final_prop_type = callee_type
                        if is_pointer_type(callee_type):
                            final_prop_type = None
                            print("[Alignment] Callee '{}' -> Caller '{}': name propagated, but type propagation skipped for pointer type on local variable '{}'".format(
                                callee_name, caller_func.getName(), a))

                        caller_var_updates.append({
                            "name": a,
                            "new_name": callee_old_name,
                            "new_type": final_prop_type
                        })
                        print("[Alignment] Callee '{}' -> Caller '{}': renaming variable '{}' -> '{}'{}".format(
                            callee_name, caller_func.getName(), a, callee_old_name,
                            " and propagating type" if final_prop_type else ""))
                        
                    new_callee_params.add(ParameterImpl(proposed_callee_name, proposed_callee_type, program))
                
            if callee_changed:
                change_function_parameters(
                    program, callee_func, new_callee_params,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS
                )
                
    if caller_var_updates:
        unique_updates = []
        seen = set()
        for u in caller_var_updates:
            if u["name"] not in seen:
                seen.add(u["name"])
                unique_updates.append(u)
        update_variable_names_and_types(program, caller_func, unique_updates)

def enhance_decompilation_with_ai(program, iface, core_funcs, skip_ai_for_funcs=None, model="llama3.1-8b"):
    """
    Reusable wrapper that coordinates the full pipeline of semantic updates, 
    AI variable/name suggestions, and intelligent parameter propagation.
    
    Parameters
    ----------
    program           : ghidra.program.model.listing.Program
    iface             : ghidra.app.decompiler.DecompInterface
    core_funcs        : dict
        Mapping of { "function_name": FunctionObject } indicating which functions to process.
    skip_ai_for_funcs : list
        List of function names that should bypass AI querying (e.g., 'main' because it has a standard signature).
    model : str
        The Cerebras model ID to use.
    """
    from ghidra.util.task import ConsoleTaskMonitor
    from cerebras_suggestions import get_cerebras_suggestions
    
    if skip_ai_for_funcs is None:
        skip_ai_for_funcs = []

    # Pre-Pass: Identify 'main' or entry point to use as global reference context
    global_context_c = None
    main_func = core_funcs.get("main")
    if not main_func:
        # Fallback to the first function in core_funcs if 'main' isn't explicitly named
        main_func = next(iter(core_funcs.values())) if core_funcs else None
    
    if main_func:
        print(f"[Context] Using '{main_func.getName()}' as global reference for AI consistency.")
        m_results = iface.decompileFunction(main_func, 30, ConsoleTaskMonitor())
        if m_results.decompileCompleted():
            global_context_c = m_results.getDecompiledFunction().getC()

    # Pass 1: Setup basic semantics and gather LLM suggestions
    stored_suggestions = {}
    for name, func in core_funcs.items():
        # Update semantics (return type, param commit) via Ghidra analysis
        update_function_semantics(program, func, name)

        if name not in skip_ai_for_funcs:
            print(f"[Cerebras] Requesting suggestions for '{name}' ...")
            dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
            if dec_results.decompileCompleted():
                initial_c = dec_results.getDecompiledFunction().getC()
                # Pass global_context_c for consistency
                suggestions = get_cerebras_suggestions(initial_c, model=model, context_c=global_context_c)
                if suggestions:
                    stored_suggestions[name] = suggestions

    # Pass 2: Apply all LLM suggestions (function names, variables, parameters)
    for name, func in core_funcs.items():
        if name in stored_suggestions:
            apply_cerebras_suggestions(program, func, stored_suggestions[name])

    # Pass 3 & 4: Deep alignment (two passes ensure names propagate multiple levels deep)
    for pass_num in [1, 2]:
        print(f"[Alignment] Starting global alignment pass {pass_num}/2 ...")
        for name, func in core_funcs.items():
            dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
            if dec_results.decompileCompleted():
                aligned_c = dec_results.getDecompiledFunction().getC()
                # Align calls inside this function to its callees (and vice-versa)
                align_usage_with_called_functions(program, func, aligned_c, core_funcs.values())
            
    return stored_suggestions
