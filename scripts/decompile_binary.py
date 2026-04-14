#!/usr/bin/env python3
"""
scripts/decompile_binary.py
----------------------------
Entry-point script: loads a binary with PyGhidra, runs the full AI-enhanced
decompilation pipeline, and writes the sanitized C output to output/.

Usage
-----
    python scripts/decompile_binary.py

Configuration
-------------
    Edit BINARY_PATH below (or set it via environment variable BINARY_PATH).
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
    strip_leading_underscores,
    sanitize_c_code,
    getCoreFunctions,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BINARY_PATH = os.environ.get(
    "BINARY_PATH",
    "/Users/pranaysompalli/Downloads/hello_stripped",
)

OUTPUT_DIR = os.path.join(_repo_root, "output")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_decompiler():
    # Start PyGhidra fully in headless mode first
    pyghidra.start()

    # Imports requiring JVM
    from java.io import File

    builder = pyghidra.program_loader()
    builder.source(File(BINARY_PATH))

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
    stored_suggestions = enhance_decompilation_with_ai(
        program, iface, core_funcs, skip_ai_for_funcs=["main"]
    )

    # ── Final pass: collect headers/defines then re-decompile ────────────────
    all_includes = set()
    all_defines  = set()
    for suggestions in stored_suggestions.values():
        all_includes.update(suggestions.get("includes", []))
        all_defines.update(suggestions.get("defines", []))

    final_output = []

    for inc in sorted(all_includes):
        if not inc.strip().startswith("#include"):
            final_output.append(f"#include {inc.strip()}")
        else:
            final_output.append(inc.strip())

    for dfn in sorted(all_defines):
        final_output.append(dfn.strip())

    if final_output:
        final_output.append("")

    # Callees before callers (bottom-up ordering via reversed insertion order)
    for name, func in reversed(list(core_funcs.items())):
        print(f"\n/* --- Function: {func.getName()} --- */")
        dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
        if dec_results.decompileCompleted():
            final_c = dec_results.getDecompiledFunction().getC()
            final_c = sanitize_c_code(final_c)
            print(final_c)
            final_output.append(f"/* --- Function: {func.getName()} --- */\n")
            final_output.append(final_c)

    # Write output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_filename = os.path.join(
        OUTPUT_DIR,
        f"{os.path.basename(BINARY_PATH)}_decompiled.c",
    )

    with open(output_filename, "w") as f:
        f.write("\n".join(final_output))

    print(f"\nSuccessfully stored decompiled program in {output_filename}")

    # Release consumer when done
    res.release(None)


if __name__ == "__main__":
    run_decompiler()
