#!/usr/bin/env python3
"""
scripts/decompile_binary.py
----------------------------
Entry-point script: loads a binary with PyGhidra, runs the full AI-enhanced
decompilation pipeline, and writes the sanitized C output to output/.

Usage
-----
    python scripts/decompile_binary.py <binary_name>

    <binary_name> must be a file inside the project's binaries/ directory.

Example
-------
    python scripts/decompile_binary.py crackme0x06
"""

import os
import sys

# Allow running the script from the repo root without installing the package.
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import pyghidra
from ghidra_decompiler import (
    enhance_decompilation_with_ai,
    DecompilerPipeline,
    strip_leading_underscores,
    sanitize_c_code,
    getCoreFunctions,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BINARIES_DIR = os.path.join(_repo_root, "binaries")
OUTPUT_DIR   = os.path.join(_repo_root, "output")


def _parse_args():
    import argparse
    parser = argparse.ArgumentParser(
        description="AI-enhanced Ghidra decompilation pipeline",
    )
    parser.add_argument(
        "binary",
        help="Name of the binary file inside the project's binaries/ directory",
    )
    parser.add_argument(
        "--model",
        default="openrouter/free",
        help="The OpenRouter model ID to use (default: openrouter/free)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_decompiler(binary_path, model="openrouter/free"):
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

    res     = next(iter(results))
    program = res.getDomainObject()

    # Analyze the program before decompiling (otherwise functions may be missing)
    pyghidra.api.analyze(program)

    # One-time pass: strip _s/_p leading underscores across all functions
    strip_leading_underscores(program)

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    # Initialize decompiler
    iface = DecompInterface()
    iface.openProgram(program)

    # Collect user-defined .text functions
    fm        = program.getFunctionManager()
    functions = fm.getFunctions(True)

    coreFunctions = {}
    for func in functions:
        if func.isThunk() or func.isExternal() or func.isLibrary() or func.isInline():
            continue
        section = func.getProgram().getMemory().getBlock(func.getEntryPoint()).getName()
        if section not in (".text", "__text"):
            continue
        coreFunctions[func.getName()] = func

    core_funcs = getCoreFunctions(coreFunctions, program)

    # ── AI-enhanced decompilation pipeline ──────────────────────────────────
    pipeline = DecompilerPipeline(program, iface, core_funcs, model=model)
    stored_suggestions = pipeline.execute_full_pipeline()

    # ── Final pass: collect headers/defines then re-decompile ────────────────
    all_includes = set()
    all_defines  = set()
    for suggestions in stored_suggestions.values():
        all_includes.update(suggestions.get("includes", []))
        all_defines.update(suggestions.get("defines", []))

    headers = []
    
    # 1. Standard C Headers
    standard_includes = [
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <stdbool.h>",
        "#include <string.h>"
    ]
    for inc in standard_includes:
        all_includes.add(inc)

    # Deduplicate includes — normalize bare '<header.h>' to '#include <header.h>' first
    seen_incs = set()
    for inc in sorted(all_includes):
        inc = inc.strip()
        if not inc.startswith("#include"):
            inc = "#include " + inc
        key = inc.lower()
        if key in seen_incs:
            continue
        seen_incs.add(key)
        headers.append(inc)

    headers.append("")

    # Build the C bodies first to know what types and aliases are used
    bodies = []
    
    # Custom Defines from AI (normalize and validate)
    import re as _re
    for dfn in sorted(all_defines):
        dfn = dfn.strip()
        if not dfn.startswith("#define"):
            dfn = "#define " + dfn
        # Reject bare '#define SYMBOL' with no value — these are LLM hallucinations
        # that would silently erase every occurrence of that symbol in the code.
        parts = dfn.split()
        if len(parts) < 3:
            print("[Sanitize] Dropping malformed define (no value): {}".format(dfn))
            continue
        bodies.append(dfn)

    if all_defines:
        bodies.append("")
        
    # Extract and emit Global Variables
    from ghidra.program.model.symbol import SymbolType
    globals_c = []
    emitted_globals = set()
    # ELF/linker noise symbols to always exclude from the C output
    _LINKER_NOISE = {
        "data_start", "__data_start", "__dso_handle", "__bss_start",
        "_edata", "_end", "__libc_csu_init", "__libc_csu_fini",
        "_init", "_fini", "_start",
    }
    for sym in program.getSymbolTable().getSymbolIterator():
        if sym.isGlobal() and sym.getSymbolType() == SymbolType.LABEL:
            sym_name = sym.getName()
            # Skip: already emitted, linker noise, names with dots, or leading __
            if sym_name in emitted_globals:
                continue
            if sym_name in _LINKER_NOISE:
                continue
            if '.' in sym_name or sym_name.startswith('__'):
                continue
            address = sym.getAddress()
            block = program.getMemory().getBlock(address)
            if block and not block.isExecute() and (block.getName() in [".data", ".bss", "__data", "__bss", "__common"]):
                data = program.getListing().getDataAt(address)
                if data:
                    dt = data.getDataType()
                    globals_c.append(f"{dt.getName()} {sym_name};")
                    emitted_globals.add(sym_name)
    
    if globals_c:
        bodies.append("/* Global Variables */")
        bodies.extend(globals_c)
        bodies.append("")

    # Function Prototypes
    bodies.append("/* Function Prototypes */")
    for name, func in core_funcs.items():
        bodies.append(f"{func.getSignature().getPrototypeString(True)};")
    bodies.append("")

    # Function Bodies
    for name, func in reversed(list(core_funcs.items())):
        print(f"\n/* --- Function: {func.getName()} --- */")
        dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
        if dec_results.decompileCompleted():
            final_c = dec_results.getDecompiledFunction().getC()
            final_c = sanitize_c_code(final_c)
            print(final_c)
            bodies.append(f"/* --- Function: {func.getName()} --- */\n")
            bodies.append(final_c)
            
    # Now compute dynamic typedefs and aliases
    import re
    full_c_text = " ".join(bodies)
    used_words = set(re.findall(r'\b[a-zA-Z_]\w*\b', full_c_text))

    # Dynamic Ghidra Typedefs mapping
    ghidra_type_map = {
        "undefined": "unsigned char",
        "byte": "unsigned char",
        "undefined2": "unsigned short",
        "ushort": "unsigned short",
        "undefined4": "unsigned int",
        "uint": "unsigned int",
        "undefined8": "unsigned long long",
        "ulong": "unsigned long"
    }
    
    dynamic_typedefs = []
    for gtype, ctype in ghidra_type_map.items():
        if gtype in used_words:
            dynamic_typedefs.append(f"typedef {ctype} {gtype};")
            
    if dynamic_typedefs:
        headers.append("/* Dynamic Ghidra Types */")
        headers.extend(dynamic_typedefs)
        headers.append("")

    # Dynamic Libc Aliases
    dynamic_aliases = []
    for sym in program.getSymbolTable().getExternalSymbols():
        name = sym.getName()
        if name in used_words and name.startswith("_"):
            dynamic_aliases.append(f"#define {name} {name[1:]}")
            
    if dynamic_aliases:
        headers.append("/* Dynamic Libc Aliases */")
        headers.extend(dynamic_aliases)
        headers.append("")
        
    final_output = headers + bodies



    # Write output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_filename = os.path.join(
        OUTPUT_DIR,
        f"{os.path.basename(binary_path)}_decompiled.c",
    )

    with open(output_filename, "w") as f:
        f.write("\n".join(final_output))

    # Save suggestions to JSON for the Ghidra Script to import back into the UI
    import json
    suggestions_filename = os.path.join(
        OUTPUT_DIR,
        f"{os.path.basename(binary_path)}_suggestions.json"
    )
    # Convert suggestions to a JSON-serializable format (strip non-serializable objects)
    serializable_suggestions = {}
    for name, s in stored_suggestions.items():
        serializable_suggestions[name] = {
            "name": s.get("name"),
            "variables": s.get("variables", {}),
            "parameters": s.get("parameters", []),
            "context": s.get("context", "")
        }
    
    with open(suggestions_filename, "w") as f:
        json.dump(serializable_suggestions, f, indent=4)

    print(f"\nSuccessfully stored decompiled program in {output_filename}")
    print(f"Suggestions saved to {suggestions_filename} for Ghidra UI import.")

    # Release consumer when done
    res.release(None)


if __name__ == "__main__":
    args = _parse_args()
    binary_path = os.path.join(BINARIES_DIR, args.binary)

    if not os.path.isfile(binary_path):
        print(f"Error: binary '{args.binary}' not found in {BINARIES_DIR}/")
        sys.exit(1)

    run_decompiler(binary_path, model=args.model)
