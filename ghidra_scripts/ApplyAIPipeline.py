# Apply AI suggestions from the AI Pipeline back into the Ghidra UI.
# @category Decompiler
# @keybinding 
# @menupath 
# @toolbar 

import json
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import ParameterImpl, Function
from java.util import ArrayList

def apply_suggestions():
    # Ask the user for the suggestions JSON file
    json_file = askFile("Select the suggestions JSON file", "Load")
    if not json_file or not json_file.exists():
        print("No file selected or file does not exist.")
        return

    with open(json_file.getAbsolutePath(), 'r') as f:
        suggestions = json.load(f)

    # Register custom types first
    all_custom_types = []
    for func_name, data in suggestions.items():
        if isinstance(data, dict) and "custom_types" in data:
            all_custom_types.extend(data["custom_types"])
    
    if all_custom_types:
        try:
            from ghidra_decompiler.custom_types import sanitize_custom_types, register_custom_datatypes
            sanitized_types = sanitize_custom_types(all_custom_types)
            register_custom_datatypes(currentProgram, sanitized_types)
            print("Successfully registered custom datatypes.")
        except Exception as cte:
            print("Could not register custom datatypes: {}".format(str(cte)))

    fm = currentProgram.getFunctionManager()
    
    # Start a transaction
    txId = currentProgram.startTransaction("Apply AI Pipeline Suggestions")
    try:
        for func_name, data in suggestions.items():
            # Correct way to find functions by name in Ghidra
            symbols = currentProgram.getSymbolTable().getGlobalSymbols(func_name)
            func = None
            for s in symbols:
                if s.getSymbolType().toString() == "Function":
                    func = s.getObject()
                    break
            
            if not func:
                print("Function '{}' not found in database. Skipping.".format(func_name))
                continue
            print("Applying updates to {}...".format(func_name))
            
            # 1. Update Function Comment
            if data.get("context"):
                func.setComment(data["context"])

            # 2. Update Variable Names & Types
            variables = data.get("variables", [])
            existing_vars = {v.getName(): v for v in func.getAllVariables()}
            if isinstance(variables, dict):
                for old_name, var_info in variables.items():
                    if old_name in existing_vars:
                        v = existing_vars[old_name]
                        new_name = None
                        new_type_str = None
                        if isinstance(var_info, dict):
                            new_name = var_info.get("name") or var_info.get("new_name")
                            new_type_str = var_info.get("new_type_str") or var_info.get("type_str")
                        else:
                            new_name = var_info

                        new_type = None
                        if new_type_str:
                            try:
                                from ghidra_decompiler.type_utils import resolve_type
                                new_type = resolve_type(new_type_str, currentProgram)
                            except Exception as te:
                                print("  Could not resolve type '{}': {}".format(new_type_str, str(te)))

                        try:
                            if new_type:
                                from ghidra_decompiler.type_utils import is_array_type, is_pointer_type
                                existing_type = v.getDataType()
                                if not (is_array_type(existing_type) and is_pointer_type(new_type)):
                                    v.setDataType(new_type, False, True, SourceType.USER_DEFINED)
                                    print("  Set variable type: {} -> {}".format(old_name, new_type.getName()))
                                else:
                                    print("  Skipping retype of array '{}' to pointer '{}'".format(old_name, new_type.getName()))
                            if new_name:
                                v.setName(new_name, SourceType.USER_DEFINED)
                                print("  Renamed variable: {} -> {}".format(old_name, new_name))
                        except Exception as ve:
                            print("  Could not update variable {}: {}".format(old_name, str(ve)))

            elif isinstance(variables, list):
                for var_info in variables:
                    if not isinstance(var_info, dict):
                        continue
                    old_name = var_info.get("name")
                    new_name = var_info.get("new_name")
                    new_type_str = var_info.get("new_type_str") or var_info.get("type_str")
                    if old_name and old_name in existing_vars:
                        v = existing_vars[old_name]
                        new_type = None
                        if new_type_str:
                            try:
                                from ghidra_decompiler.type_utils import resolve_type
                                new_type = resolve_type(new_type_str, currentProgram)
                            except Exception as te:
                                print("  Could not resolve type '{}': {}".format(new_type_str, str(te)))

                        try:
                            if new_type:
                                from ghidra_decompiler.type_utils import is_array_type, is_pointer_type
                                existing_type = v.getDataType()
                                if not (is_array_type(existing_type) and is_pointer_type(new_type)):
                                    v.setDataType(new_type, False, True, SourceType.USER_DEFINED)
                                    print("  Set variable type: {} -> {}".format(old_name, new_type.getName()))
                                else:
                                    print("  Skipping retype of array '{}' to pointer '{}'".format(old_name, new_type.getName()))
                            if new_name:
                                v.setName(new_name, SourceType.USER_DEFINED)
                                print("  Renamed variable: {} -> {}".format(old_name, new_name))
                        except Exception as ve:
                            print("  Could not update variable {}: {}".format(old_name, str(ve)))

            # 3. Update Parameters
            parameters = data.get("parameters", [])
            existing_params = {p.getName(): p for p in func.getParameters()}
            for param_info in parameters:
                if not isinstance(param_info, dict):
                    continue
                old_name = param_info.get("name")
                new_name = param_info.get("new_name")
                new_type_str = param_info.get("new_type_str") or param_info.get("type_str")
                if old_name and old_name in existing_params:
                    p = existing_params[old_name]
                    new_type = None
                    if new_type_str:
                        try:
                            from ghidra_decompiler.type_utils import resolve_type
                            new_type = resolve_type(new_type_str, currentProgram)
                        except Exception as te:
                            print("  Could not resolve parameter type '{}': {}".format(new_type_str, str(te)))
                    try:
                        if new_type:
                            from ghidra_decompiler.type_utils import is_array_type, is_pointer_type
                            existing_type = p.getDataType()
                            if not (is_array_type(existing_type) and is_pointer_type(new_type)):
                                p.setDataType(new_type, False, True, SourceType.USER_DEFINED)
                                print("  Set parameter type: {} -> {}".format(old_name, new_type.getName()))
                            else:
                                print("  Skipping parameter retype of array '{}' to pointer '{}'".format(old_name, new_type.getName()))
                        if new_name:
                            p.setName(new_name, SourceType.USER_DEFINED)
                            print("  Renamed parameter: {} -> {}".format(old_name, new_name))
                    except Exception as pe:
                        print("  Could not update parameter {}: {}".format(old_name, str(pe)))

            # 4. Rename Function
            suggested_func_name = data.get("function_name")
            if suggested_func_name and suggested_func_name != func_name:
                try:
                    func.setName(suggested_func_name, SourceType.USER_DEFINED)
                    print("  Renamed function: {} -> {}".format(func_name, suggested_func_name))
                except Exception as fe:
                    print("  Could not rename function {} to {}: {}".format(func_name, suggested_func_name, str(fe)))

        print("Successfully applied AI suggestions to the Ghidra UI!")
    except Exception as e:
        print("Error applying suggestions: {}".format(str(e)))
    finally:
        currentProgram.endTransaction(txId, True)

if __name__ == "__main__":
    apply_suggestions()
