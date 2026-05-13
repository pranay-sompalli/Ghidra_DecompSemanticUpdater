# Apply AI suggestions from the Gemini Pipeline back into the Ghidra UI.
# @author Antigravity
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

            # 2. Update Variable Names
            variables = data.get("variables", {})
            existing_vars = {v.getName(): v for v in func.getAllVariables()}
            for old_name, var_info in variables.items():
                if old_name in existing_vars:
                    v = existing_vars[old_name]
                    new_name = var_info.get("name")
                    if new_name:
                        try:
                            v.setName(new_name, SourceType.USER_DEFINED)
                            print("  Renamed variable: {} -> {}".format(old_name, new_name))
                        except Exception as ve:
                            print("  Could not rename {} to {}: {}".format(old_name, new_name, str(ve)))

            # 3. Update Parameters (Simple case)
            # Note: Complex signature updates (argc/argv) are best done in the main pipeline,
            # but we can apply the names here if we have them.
            
        print("Successfully applied AI suggestions to the Ghidra UI!")
    except Exception as e:
        print("Error applying suggestions: {}".format(str(e)))
    finally:
        currentProgram.endTransaction(txId, True)

if __name__ == "__main__":
    apply_suggestions()
