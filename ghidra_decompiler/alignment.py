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
    - If caller passes a meaningful variable name to a callee's generic parameter,
      renames the callee's parameter.
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

        pattern = r'\b' + re.escape(callee_name) + r'\s*\(([^)]*)\)'
        for match in re.finditer(pattern, caller_c_code):
            args = [a.strip() for a in match.group(1).split(",")]

            callee_params    = list(callee_func.getParameters())
            new_callee_params = ArrayList()
            callee_changed   = False
            callee_var_names = {v.getName() for v in callee_func.getAllVariables()}

            for i, a in enumerate(args):
                a = clean_c_argument(a)

                caller_has_good_name = re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', a) and not is_generic_name(a)
                caller_is_generic    = re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', a) and is_generic_name(a)

                callee_old_name  = callee_params[i].getName() if i < len(callee_params) else None
                callee_has_good_name = callee_old_name and not is_generic_name(callee_old_name)
                callee_is_generic    = callee_old_name and is_generic_name(callee_old_name)  # noqa: F841

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
                            print("[Alignment] Callee '{}' already has a variable named '{}'. "
                                  "Skipping rename to avoid collision.".format(callee_name, a))
                        else:
                            proposed_callee_name = a
                            print("[Alignment] Caller '{}' -> Callee '{}' arg {}: renaming param '{}' -> '{}'".format(
                                caller_func.getName(), callee_name, i, callee_old_name, a))
                            callee_changed = True
                            callee_var_names.add(a)

                    elif callee_has_good_name and caller_is_generic:
                        callee_type     = callee_params[i].getDataType()
                        final_prop_type = callee_type

                        if is_pointer_type(callee_type):
                            final_prop_type = None
                            print("[Alignment] Callee '{}' -> Caller '{}': name propagated, but type propagation "
                                  "skipped for pointer type on local variable '{}'".format(
                                      callee_name, caller_func.getName(), a))

                        caller_var_updates.append({
                            "name":     a,
                            "new_name": callee_old_name,
                            "new_type": final_prop_type,
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
        # Deduplicate updates (keep first occurrence per variable name)
        unique_updates = []
        seen = set()
        for u in caller_var_updates:
            if u["name"] not in seen:
                seen.add(u["name"])
                unique_updates.append(u)
        update_variable_names_and_types(program, caller_func, unique_updates)
