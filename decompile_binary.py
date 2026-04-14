import pyghidra
from update_semantics import strip_leading_underscores, sanitize_c_code
from coreFunctions import getCoreFunctions

# Path to the binary you want to decompile
binary_path = "/Users/pranaysompalli/Downloads/crackme0x06" 

def run_decompiler():
    # Start PyGhidra fully in headless mode first
    pyghidra.start()

    # Imports requiring JVM
    from java.io import File
    
    builder = pyghidra.program_loader()
    builder.source(File(binary_path))
    
    # Load the program
    results = builder.load()
    if not results:
        print("Failed to load program.")
        return
        
    res = next(iter(results))
    program = res.getDomainObject()
    
    # Analyze the program before decompiling it! (Otherwise there might not be functions)
    pyghidra.api.analyze(program)
    
    # One-time pass: strip _s/_p leading underscores across all functions
    strip_leading_underscores(program)
    
    
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    
    # Initialize decompiler using the program attribute
    iface = DecompInterface()
    iface.openProgram(program)
    
    # Access functions via the program attribute
    fm = program.getFunctionManager()
    functions = fm.getFunctions(True)
    
    coreFunctions = {}
    for func in functions:
        if func.isThunk() or func.isExternal() or func.isLibrary() or func.isInline():
            continue
            
        section = func.getProgram().getMemory().getBlock(func.getEntryPoint()).getName()
        if section not in (".text", "__text"):
            continue
        
        coreFunctions[func.getName()]=func

    core_funcs = getCoreFunctions(coreFunctions, program)

    # ── Execute Reusable AI Decompilation Pipeline ───────────────────────────
    from update_semantics import enhance_decompilation_with_ai
    stored_suggestions = enhance_decompilation_with_ai(program, iface, core_funcs, skip_ai_for_funcs=["main"])

    # Pass 4: Final re-decompile and save to file
    import os
    all_includes = set()
    all_defines = set()
    for suggestions in stored_suggestions.values():
        all_includes.update(suggestions.get("includes", []))
        all_defines.update(suggestions.get("defines", []))

    final_output = []
    
    for inc in sorted(list(all_includes)):
        if not inc.strip().startswith("#include"):
            final_output.append(f"#include {inc.strip()}")
        else:
            final_output.append(inc.strip())
            
    for dfn in sorted(list(all_defines)):
        final_output.append(dfn.strip())
        
    if final_output:
        final_output.append("")

    # Use reversed list to ensure callees appear before callers (bottom-up ordering)
    for name, func in reversed(list(core_funcs.items())):
        print(f"\n/* --- Function: {func.getName()} --- */")
        dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
        if dec_results.decompileCompleted():
            final_c = dec_results.getDecompiledFunction().getC()
            final_c = sanitize_c_code(final_c)
            print(final_c)
            final_output.append(f"/* --- Function: {func.getName()} --- */\n")
            final_output.append(final_c)

    output_dir = "decompiled_files"
    os.makedirs(output_dir, exist_ok=True)
    output_filename = os.path.join(output_dir, f"{os.path.basename(binary_path)}_decompiled.c")
    
    with open(output_filename, "w") as f:
        f.write("\n".join(final_output))
        
    print(f"\nSuccessfully stored decompiled program with includes/defines in {output_filename}")

    # Release consumer when done
    res.release(None)

if __name__ == "__main__":
    run_decompiler()
