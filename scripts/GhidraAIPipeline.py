# Run End-to-End AI Decompilation Pipeline directly inside Ghidra GUI
# @category=Spring2026.GhidraScripts
# @keybinding ctrl alt a
# @menupath Tools.AI.Run AI Decompiler Pipeline

import os
import json
import sys

# Ensure the ReverseEngineeringProject root is in the Python path so pyghidra can import our modules
project_root = "/Users/pranaysompalli/Documents/ReverseEngineeringProject"

if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Inject standard macOS Python site-packages paths so Ghidra GUI's embedded
# Python interpreter can locate third-party dependencies like 'openai'.
site_packages = [
    "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages",
    "/Users/pranaysompalli/Library/Python/3.13/lib/python/site-packages"
]
for sp in site_packages:
    if sp not in sys.path and os.path.exists(sp):
        sys.path.append(sp)

try:
    import ghidra_decompiler
    import ghidra_decompiler.gui_utils
    import ghidra_decompiler.gui_utils.optimizer
    import importlib
    importlib.reload(ghidra_decompiler.gui_utils.optimizer)
    importlib.reload(ghidra_decompiler.gui_utils)
    importlib.reload(ghidra_decompiler)

    from ghidra_decompiler import (
        DecompilerPipeline,
        strip_leading_underscores,
        getCoreFunctions,
    )
    from ghidra_decompiler.gui_utils import optimize_gui_function_variables
except ImportError:
    print("[Error] Could not import ghidra_decompiler package.")
    print("Please ensure project_root path is absolute and correct.")
    sys.exit(1)


def run():
    # currentProgram, askString, getMonitor are injected by Ghidra GUI flat API
    try:
        prog = currentProgram
    except NameError:
        print("[Error] currentProgram is undefined. This script must be run inside Ghidra GUI.")
        return

    # 1. Ask user for OpenRouter API Key if not in environment
    api_key = os.environ.get("OPEN_ROUTER_API_KEY")
    if not api_key:
        api_key = askString("OpenRouter API Key", "Please enter your OpenRouter API Key (sk-or-v1-...):")
        if not api_key:
            print("[Cancel] No API key provided.")
            return
        os.environ["OPEN_ROUTER_API_KEY"] = api_key.strip()

    # 2. Ask user for Model Selection
    model = askString("Model Selection", "Enter OpenRouter Model ID:", "openai/gpt-oss-120b:free")
    if not model:
        model = "openrouter/free"
    else:
        model = model.strip()

    print(f"[Pipeline] Starting End-to-End AI Decompilation for: {prog.getName()}")
    print(f"[Pipeline] Using Model: {model}")

    # Wrap the Ghidra database modification phase in an undoable transaction
    tx_id = prog.startTransaction("AI Decompilation Pipeline")
    try:
        # Strip leading underscores across all functions first (same as headless)
        strip_leading_underscores(prog)

        from ghidra.app.decompiler import DecompInterface

        # Initialize native Decompiler Interface using GUI context
        iface = DecompInterface()
        iface.openProgram(prog)

        # Collect user-defined .text functions
        fm = prog.getFunctionManager()
        functions = fm.getFunctions(True)

        coreFunctions = {}
        for func in functions:
            if func.isThunk() or func.isExternal() or func.isLibrary() or func.isInline():
                continue
            # Filter to .text section
            block = prog.getMemory().getBlock(func.getEntryPoint())
            if block and block.getName() in (".text", "__text"):
                coreFunctions[func.getName()] = func

        # Filter out compiler intrinsics and thunks using our backend logic
        core_funcs = getCoreFunctions(coreFunctions, prog)
        print(f"[Pipeline] Identified {len(core_funcs)} core function(s) for AI processing.")

        # ── Execute Full Pipeline (Queries LLM + Commits Suggestions to DB) ──
        pipeline = DecompilerPipeline(prog, iface, core_funcs, model=model)
        # execute_full_pipeline runs semantic pass, queries LLM, and calls apply_suggestions internally
        stored_suggestions = pipeline.execute_full_pipeline()

        # ── Optional GUI Optimization Pass: Strip dead captures via P-Code Split ──
        print("\n[Pipeline] Running P-Code variable optimization pass to strip dead captures...")
        monitor = getMonitor() if 'getMonitor' in globals() else None
        for func in core_funcs.values():
            optimize_gui_function_variables(prog, func, monitor)

        # Save resulting suggestions map to a JSON file in the same directory as the binary
        # or fall back to user's home/desktop directory if program path is virtual.
        prog_path = prog.getExecutablePath()
        if prog_path and os.path.exists(os.path.dirname(prog_path)):
            out_dir = os.path.dirname(prog_path)
        else:
            out_dir = os.path.expanduser("~/Desktop")

        json_name = f"{os.path.splitext(prog.getName())[0]}_gui_suggestions.json"
        json_path = os.path.join(out_dir, json_name)

        print(f"\n[Pipeline] Writing JSON suggestions map to: {json_path}")
        with open(json_path, "w") as f:
            json.load(f) if False else json.dump(stored_suggestions, f, indent=2)

        print("\n[Success] AI Decompiler Pipeline execution completed successfully!")
    except Exception as e:
        import traceback
        print(f"[Error] Pipeline execution failed: {e}")
        traceback.print_exc()
        prog.endTransaction(tx_id, False) # rollback Ghidra database changes on error
    else:
        prog.endTransaction(tx_id, True)  # commit changes to GUI database
    finally:
        if 'iface' in locals():
            iface.dispose()


if __name__ == "__main__":
    run()
