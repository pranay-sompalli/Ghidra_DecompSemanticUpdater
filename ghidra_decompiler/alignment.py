"""
ghidra_decompiler.alignment
-----------------------------
Cross-function naming alignment pass for the decompilation pipeline.

Parses caller decompiled C code to find calls to known core functions and
propagates meaningful variable/parameter names in both directions.

Public API
----------
    align_usage_with_called_functions(program, caller_func, caller_c_code, core_functions)
"""

import re

from ghidra_decompiler.code_utils import is_generic_name, clean_c_argument
from ghidra_decompiler.type_utils import is_pointer_type
from ghidra_decompiler.semantics import change_function_parameters, update_variable_names_and_types


def align_usage_with_called_functions(program, caller_func, caller_c_code, core_functions):
    """
    Parse the decompiled C code of a caller function to find calls to core functions.
    Aligns naming usage:
    - If caller passes a meaningful variable name to a callee's parameter,
      renames the callee's parameter to match for consistency.
    - If callee has a meaningful parameter name but caller passes a generic variable,
      renames the caller's variable.
    """
    from ghidra.program.model.listing import ParameterImpl, Function
    from java.util import ArrayList

    caller_var_updates = []
    caller_vars = {v.getName(): v for v in caller_func.getAllVariables()}

    for callee_func in core_functions:
        callee_name = callee_func.getName()
        if callee_name == caller_func.getName():
            continue

        # Regex to find function calls.
        pattern = r'\b' + re.escape(callee_name) + r'\s*\(([^;]*?)\)\s*[;{]'
        for match in re.finditer(pattern, caller_c_code):
            raw_args = match.group(1)
            args = [a.strip() for a in raw_args.split(",")]

            callee_params    = list(callee_func.getParameters())
            new_callee_params = ArrayList()
            callee_changed   = False
            callee_var_names = {v.getName() for v in callee_func.getAllVariables()}

            for i, a in enumerate(args):
                if i >= len(callee_params):
                    break

                clean_arg = clean_c_argument(a)

                # A "good name" is any name that is not a Ghidra auto-generated generic name.
                caller_has_good_name = re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', clean_arg) and not is_generic_name(clean_arg)
                caller_is_generic    = re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', clean_arg) and is_generic_name(clean_arg)

                callee_old_name  = callee_params[i].getName()
                callee_has_good_name = callee_old_name and not is_generic_name(callee_old_name)

                proposed_callee_name = callee_old_name
                proposed_callee_type = callee_params[i].getDataType()

                # 1. Type Propagation (Caller -> Callee)
                if clean_arg in caller_vars:
                    caller_type = caller_vars[clean_arg].getDataType()
                    if str(proposed_callee_type) != str(caller_type) and "undefined" not in str(caller_type):
                        proposed_callee_type = caller_type
                        callee_changed = True
                        print("[Alignment] Caller '{}' -> Callee '{}' arg {}: propagating type '{}'".format(
                            caller_func.getName(), callee_name, i, caller_type))

                # 2. Name Propagation (Caller -> Callee)
                # If caller has a meaningful name, always propagate it down to the callee.
                if caller_has_good_name and callee_old_name != clean_arg:
                    if clean_arg in callee_var_names and clean_arg != callee_old_name:
                        print("[Alignment] Callee '{}' already has a variable named '{}'. Skipping rename.".format(
                            callee_name, clean_arg))
                    else:
                        proposed_callee_name = clean_arg
                        print("[Alignment] Caller '{}' -> Callee '{}' arg {}: renaming param '{}' -> '{}'".format(
                            caller_func.getName(), callee_name, i, callee_old_name, clean_arg))
                        callee_changed = True
                        callee_var_names.add(clean_arg)

                # 3. Name Propagation (Callee -> Caller)
                elif callee_has_good_name and caller_is_generic:
                    callee_type     = callee_params[i].getDataType()
                    final_prop_type = callee_type

                    if is_pointer_type(callee_type):
                        final_prop_type = None  # Avoid unsafe pointer propagation to stack vars

                    caller_var_updates.append({
                        "name":     clean_arg,
                        "new_name": callee_old_name,
                        "new_type": final_prop_type,
                    })
                    print("[Alignment] Callee '{}' -> Caller '{}': renaming variable '{}' -> '{}'".format(
                        callee_name, caller_func.getName(), clean_arg, callee_old_name))

                new_callee_params.add(ParameterImpl(proposed_callee_name, proposed_callee_type, program))

            if callee_changed:
                change_function_parameters(
                    program, callee_func, new_callee_params,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS
                )

    if caller_var_updates:
        # Deduplicate updates
        unique_updates = []
        seen = set()
        for u in caller_var_updates:
            if u["name"] not in seen:
                seen.add(u["name"])
                unique_updates.append(u)
        update_variable_names_and_types(program, caller_func, unique_updates)

