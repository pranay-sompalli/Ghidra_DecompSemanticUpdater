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
from ghidra_decompiler.platform_utils import (
    describe_platform,
    get_text_section_names,
    get_data_section_names,
    get_linker_noise_symbols,
    get_ghidra_type_map,
    get_calling_convention_tokens,
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
    parser.add_argument(
        '-c', '--clear-cache', 
        action='store_true',
        help='Clear the persistent cross-binary MD5 file cache before running'
    )
    return parser.parse_args()


def _format_c_field(type_str, name):
    import re
    # Check if it's an array, e.g. "char[48]" or "int [10]"
    match = re.match(r'^(.+?)\s*\[\s*(\d+)\s*\]$', type_str.strip())
    if match:
        elem_type = match.group(1).strip()
        arr_len = match.group(2)
        return f"{elem_type} {name}[{arr_len}];"
    return f"{type_str} {name};"


def _generate_custom_type_definitions(stored_suggestions, program):
    from ghidra_decompiler.custom_types import sanitize_custom_types
    from ghidra_decompiler.type_utils import resolve_type, parse_array_type
    import re
    
    # 1. Collect all custom types
    all_custom_types = []
    seen_type_names = set()
    for suggestions in stored_suggestions.values():
        for ct in suggestions.get("custom_types", []):
            ct_name = ct.get("name")
            if ct_name and ct_name not in seen_type_names:
                seen_type_names.add(ct_name)
                all_custom_types.append(ct)
                
    sanitized_custom_types = sanitize_custom_types(all_custom_types)
    if not sanitized_custom_types:
        return []
        
    definitions = []
    for ct in sanitized_custom_types:
        ct_name = ct.get("name")
        clean_name = re.sub(r'^(struct|enum|union)\s+', '', ct_name).strip()
        ct_type = ct.get("type")
        
        if ct_type == "struct":
            lines = [f"typedef struct {clean_name} {{"]
            current_offset = 0
            sorted_fields = sorted(ct.get("fields", []), key=lambda f: f.get("offset", 0))
            for field in sorted_fields:
                offset = field.get("offset", 0)
                f_name = field.get("name")
                f_type_str = field.get("type_str")
                
                # Resolve field size
                resolved = parse_array_type(f_type_str, program) or resolve_type(f_type_str, program)
                f_len = resolved.getLength() if resolved else 4
                
                if offset > current_offset:
                    lines.append(f"    char _pad_{current_offset}[{offset - current_offset}];")
                lines.append(f"    {_format_c_field(f_type_str, f_name)}")
                current_offset = offset + f_len
            lines.append(f"}} {clean_name};")
            definitions.append("\n".join(lines))
            
        elif ct_type == "union":
            lines = [f"typedef union {clean_name} {{"]
            for field in ct.get("fields", []):
                f_name = field.get("name")
                f_type_str = field.get("type_str")
                lines.append(f"    {_format_c_field(f_type_str, f_name)}")
            lines.append(f"}} {clean_name};")
            definitions.append("\n".join(lines))
            
        elif ct_type == "enum":
            lines = [f"typedef enum {clean_name} {{"]
            val_strings = []
            for val in ct.get("values", []):
                val_strings.append(f"    {val['name']} = {val['value']}")
            lines.append(",\n".join(val_strings))
            lines.append(f"}} {clean_name};")
            definitions.append("\n".join(lines))
            
    return definitions


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

    # ── Detect binary format and architecture ───────────────────────────────────────
    fmt, arch = describe_platform(program)
    _TEXT_SECTIONS = get_text_section_names(fmt)
    _DATA_SECTIONS = get_data_section_names(fmt)
    _LINKER_NOISE  = get_linker_noise_symbols(fmt)

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
        if section not in _TEXT_SECTIONS:
            continue
        coreFunctions[func.getName()] = func

    core_funcs = getCoreFunctions(coreFunctions, program)

    # ── AI-enhanced decompilation pipeline ──────────────────────────────────
    pipeline = DecompilerPipeline(program, iface, core_funcs, model=model)
    stored_suggestions = pipeline.execute_full_pipeline(clear_cache=args.clear_cache)

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

    # Decompile all functions first to know what types, variables, and aliases are used
    function_bodies = []
    for name, func in reversed(list(core_funcs.items())):
        print(f"\n/* --- Function: {func.getName()} --- */")
        dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
        if dec_results.decompileCompleted():
            final_c = dec_results.getDecompiledFunction().getC()
            final_c = sanitize_c_code(final_c)
            print(final_c)
            function_bodies.append(f"/* --- Function: {func.getName()} --- */\n")
            function_bodies.append(final_c)
        else:
            print("Decompile failed: " + str(dec_results.getErrorMessage()))

    import re
    full_c_text = " ".join(function_bodies)
    used_words = set(re.findall(r'\b[a-zA-Z_]\w*\b', full_c_text))

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

    # 2. Custom Defines from AI (normalize and validate)
    custom_defines = []
    for dfn in sorted(all_defines):
        dfn = dfn.strip()
        if not dfn.startswith("#define"):
            dfn = "#define " + dfn
        parts = dfn.split()
        if len(parts) < 3:
            print("[Sanitize] Dropping malformed define (no value): {}".format(dfn))
            continue
        custom_defines.append(dfn)

    if custom_defines:
        headers.extend(custom_defines)
        headers.append("")

    # 3. Custom Recovered Datatypes — from LLM suggestions
    custom_typedefs = _generate_custom_type_definitions(stored_suggestions, program)
    seen_custom_type_names = set()
    for defn in custom_typedefs:
        # Extract the type name from the first line (e.g. 'typedef struct Character {')
        m = re.match(r'typedef\s+(?:struct|union|enum)\s+(\w+)', defn)
        if m:
            seen_custom_type_names.add(m.group(1))

    # DTM fallback: if the code references custom types already registered in /Recovered_Types
    # but the LLM didn't re-suggest them this run, pull their definitions from Ghidra's DTM.
    _struct_var_re = re.compile(r'^\s*([A-Z][a-zA-Z0-9_]*)\s+\w+\s*;', re.MULTILINE)
    referenced_types = {m.group(1) for m in _struct_var_re.finditer(full_c_text)}
    dtm_fallback_typedefs = []
    for type_name in sorted(referenced_types - seen_custom_type_names):
        from ghidra.program.model.data import StructureDataType, UnionDataType, EnumDataType
        dt = (program.getDataTypeManager().getDataType("/Recovered_Types/" + type_name)
              or program.getDataTypeManager().getDataType("/" + type_name))
        if dt is None:
            continue
        if isinstance(dt, StructureDataType):
            lines = [f"typedef struct {type_name} {{"]
            for comp in dt.getDefinedComponents():
                f_name = comp.getFieldName() or f"_field_{comp.getOffset()}"
                f_type = comp.getDataType()
                base   = f_type.getName()
                lines.append(f"    {_format_c_field(base, f_name)}")
            lines.append(f"}} {type_name};")
            dtm_fallback_typedefs.append("\n".join(lines))
        elif isinstance(dt, UnionDataType):
            lines = [f"typedef union {type_name} {{"]
            for comp in dt.getDefinedComponents():
                f_name = comp.getFieldName() or f"_field_{comp.getOffset()}"
                f_type = comp.getDataType()
                lines.append(f"    {_format_c_field(f_type.getName(), f_name)}")
            lines.append(f"}} {type_name};")
            dtm_fallback_typedefs.append("\n".join(lines))
        elif isinstance(dt, EnumDataType):
            lines = [f"typedef enum {type_name} {{"]
            val_strings = [f"    {dt.getName(v)} = {v}" for v in dt.getValues()]
            lines.append(",\n".join(val_strings))
            lines.append(f"}} {type_name};")
            dtm_fallback_typedefs.append("\n".join(lines))

    all_custom_typedefs = custom_typedefs + dtm_fallback_typedefs
    if all_custom_typedefs:
        headers.append("/* Custom Recovered Datatypes */")
        headers.extend(all_custom_typedefs)
        headers.append("")

    # 4. Dynamic Ghidra Typedefs — architecture-aware
    ghidra_type_map = get_ghidra_type_map(arch)
    dynamic_typedefs = []
    for gtype, ctype in ghidra_type_map.items():
        if gtype in used_words:
            dynamic_typedefs.append(f"typedef {ctype} {gtype};")
            
    if dynamic_typedefs:
        headers.append("/* Dynamic Ghidra Types */")
        headers.extend(dynamic_typedefs)
        headers.append("")

    # 5. Global Variables
    from ghidra.program.model.symbol import SymbolType
    globals_c = []
    emitted_globals = set()
    for sym in program.getSymbolTable().getAllSymbols(True):
        if not sym.isGlobal():
            continue
        sym_name = sym.getName()
        if sym_name in emitted_globals:
            continue
        if sym_name in _LINKER_NOISE:
            continue
        if '.' in sym_name:
            continue
        if sym.getSymbolType() == SymbolType.FUNCTION:
            continue

        address = sym.getAddress()
        block = program.getMemory().getBlock(address)
        if block and block.isExecute():
            continue

        is_in_data_sec = block and block.getName() in _DATA_SECTIONS
        is_referenced = sym_name in used_words

        if is_in_data_sec or is_referenced:
            # Check if this name is actually called as a function (e.g. __stack_chk_fail)
            is_called = bool(re.search(r'\b' + re.escape(sym_name) + r'\s*\(', full_c_text))
            if is_called:
                continue

            dt_name = "void *"
            if address:
                data = program.getListing().getDataAt(address)
                if data:
                    dt_name = data.getDataType().getName()
            if dt_name == "undefined":
                dt_name = "void *"

            # Check if it is an imported variable (resides in EXTERNAL or got blocks)
            is_extern = block and block.getName() in ("EXTERNAL", "%got", ".got", ".got.plt")
            prefix = "extern " if is_extern else ""

            globals_c.append(f"{prefix}{_format_c_field(dt_name, sym_name)}")
            emitted_globals.add(sym_name)

    if globals_c:
        headers.append("/* Global Variables */")
        headers.extend(globals_c)
        headers.append("")

    # 6. External compiler helper prototypes
    external_helpers_c = []
    for sym in program.getSymbolTable().getAllSymbols(True):
        if not sym.isGlobal():
            continue
        sym_name = sym.getName()
        if sym_name in emitted_globals or sym_name in _LINKER_NOISE:
            continue
        if '.' in sym_name:
            continue

        is_called = bool(re.search(r'\b' + re.escape(sym_name) + r'\s*\(', full_c_text))
        if is_called and sym_name.startswith("__"):
            if sym_name == "__stack_chk_fail":
                external_helpers_c.append(f"void {sym_name}(void *__a, ...);")
            else:
                external_helpers_c.append(f"void {sym_name}();")
            emitted_globals.add(sym_name)

    if external_helpers_c:
        headers.append("/* External Compiler Helpers */")
        headers.extend(external_helpers_c)
        headers.append("")

    # 7. Dynamic Libc Aliases
    dynamic_aliases = []
    if fmt in ("MACHO", "PE"):
        for sym in program.getSymbolTable().getExternalSymbols():
            name = sym.getName()
            if name in used_words and name.startswith("_") and not name.startswith("__"):
                dynamic_aliases.append(f"#define {name} {name[1:]}")
            
    if dynamic_aliases:
        headers.append("/* Dynamic Libc Aliases */")
        headers.extend(dynamic_aliases)
        headers.append("")

    # 8. Function Prototypes
    headers.append("/* Function Prototypes */")
    for name, func in core_funcs.items():
        headers.append(f"{func.getSignature().getPrototypeString(True)};")
    headers.append("")
        
    final_output = headers + function_bodies



    # Write output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_filename = os.path.join(
        OUTPUT_DIR,
        f"{os.path.basename(binary_path)}_decompiled.c",
    )

    with open(output_filename, "w") as f:
        out_str = "\n".join(final_output)
        # Strip architecture/format-specific calling convention noise tokens globally
        out_str = re.sub(get_calling_convention_tokens(arch), '', out_str)
        # Normalize Ghidra-specific type names globally
        out_str = re.sub(r'\blonglong\b', 'long long', out_str)
        out_str = re.sub(r'\bulonglong\b', 'unsigned long long', out_str)
        out_str = re.sub(r'\bulong\b', 'unsigned long', out_str)
        out_str = re.sub(r'\buint\b', 'unsigned int', out_str)
        out_str = re.sub(r'\bushort\b', 'unsigned short', out_str)
        out_str = re.sub(r'\buchar\b', 'unsigned char', out_str)
        f.write(out_str)

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
            "name": s.get("function_name") or s.get("name"),
            "function_name": s.get("function_name") or s.get("name"),
            "variables": s.get("variables", []),
            "parameters": s.get("parameters", []),
            "globals": s.get("globals", []),
            "custom_types": s.get("custom_types", []),
            "includes": s.get("includes", []),
            "defines": s.get("defines", []),
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
