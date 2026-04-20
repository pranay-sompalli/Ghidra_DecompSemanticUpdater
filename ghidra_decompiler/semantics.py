"""
ghidra_decompiler.semantics
-----------------------------
Ghidra function and variable semantic update helpers.

All functions that write to the Ghidra database open their own transaction
so they are safe to call individually.

Public API
----------
    strip_leading_underscores(program)
    update_function_semantics(program, func, name)
    update_variable_names_and_types(program, func, updates)
    change_function_name(program, func, new_name)
    change_function_parameters(program, func, new_params, update_type=None)
    apply_cerebras_suggestions(program, func, suggestions)
"""

from ghidra_decompiler.type_utils import resolve_type, is_array_type, is_pointer_type


# ---------------------------------------------------------------------------
# Low-level Ghidra wrappers
# ---------------------------------------------------------------------------

def change_function_name(program, func, new_name):
    """
    Safely change a function's name within a transaction.
    Returns True on success, False on failure.
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


def set_function_comment(program, func, comment):
    """
    Apply a PLATE comment to the function's entry point.
    """
    from ghidra.program.model.listing import CodeUnit

    txId = program.startTransaction("Set Function Comment: " + func.getName())
    try:
        listing = program.getListing()
        code_unit = listing.getCodeUnitAt(func.getEntryPoint())
        if code_unit:
            code_unit.setComment(CodeUnit.PLATE_COMMENT, comment)
            print("[{}] Added context comment to '{}'".format(
                func.getEntryPoint(), func.getName()))
        return True
    except Exception as e:
        print("Error setting comment for {}: {}".format(func.getName(), str(e)))
        return False
    finally:
        program.endTransaction(txId, True)


def change_function_parameters(program, func, new_params, update_type=None):
    """
    Completely replace a function's parameters.

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
            True,                    # force
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


# ---------------------------------------------------------------------------
# Higher-level semantic updaters
# ---------------------------------------------------------------------------

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
          2 params -> int main(int argc, char **argv)
          3 params -> int main(int argc, char **argv, char **envp)
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
                True,                                             # useDataTypes
                HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,  # leave return type alone
                SourceType.USER_DEFINED,
            )
            # Commit local names so HighVariables (iVar1, etc.) become actual DB variables.
            HighFunctionDBUtil.commitLocalNamesToDatabase(high_func, SourceType.USER_DEFINED)

        # Step 3 – for 'main', apply canonical names and types.
        if name == "main":
            param_count = func.getParameterCount()
            if param_count in (2, 3):
                char_pp  = PointerDataType(PointerDataType(CharDataType()))
                int_type = IntegerDataType()

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
    """
    from ghidra.program.model.symbol import SourceType

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


# ---------------------------------------------------------------------------
# AI suggestion application
# ---------------------------------------------------------------------------

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
        current_name = entry.get("name")
        new_name     = entry.get("new_name")
        new_type_str = entry.get("new_type_str")
        new_type     = resolve_type(new_type_str, program) if new_type_str else None

        if (new_name and new_name != current_name) or new_type is not None:
            var_updates.append({
                "name":     current_name,
                "new_name": new_name if new_name != current_name else None,
                "new_type": new_type,
            })

    if var_updates:
        updated = update_variable_names_and_types(program, func, var_updates)
        print("[Cerebras] Applied {} variable update(s) to '{}'".format(updated, func_name))
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
        old_name   = param.getName()
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
        change_function_parameters(
            program, func, new_params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS
        )
        print("[Cerebras] Applied parameter updates to '{}'".format(func_name))
    else:
        print("[Cerebras] No parameter changes needed for '{}'".format(func_name))


def apply_cerebras_suggestions(program, func, suggestions):
    """
    Apply variable, parameter, and function name suggestions obtained from the
    Cerebras AI layer to the function in Ghidra.

    Must be called AFTER update_function_semantics() so that commitParamsToDatabase
    has already populated the function's parameter list.

    Parameters
    ----------
    program     : ghidra.program.model.listing.Program
    func        : ghidra.program.model.listing.Function
    suggestions : dict
        Precomputed dictionary of AI suggestions containing 'variables',
        'parameters', and optionally 'function_name'.
    """
    func_name = _apply_function_name_suggestion(program, func, suggestions)
    
    # Apply function context (purpose) as a header comment
    context = suggestions.get("context")
    if context:
        set_function_comment(program, func, context)

    _apply_variable_suggestions(program, func, func_name, suggestions)
    _apply_parameter_suggestions(program, func, func_name, suggestions)
