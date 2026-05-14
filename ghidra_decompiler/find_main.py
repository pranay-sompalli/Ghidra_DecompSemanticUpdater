"""
ghidra_decompiler.find_main
-----------------------------
Format-aware strategies for locating the true application entry point inside a
Ghidra program, supporting ELF (Linux), Mach-O (macOS), and PE (Windows).

Public API
----------
    find_main(coreFunctions, program) -> Function | None
"""

from ghidra_decompiler.platform_utils import (
    get_binary_format,
    get_startup_boilerplate_set,
)


# ---------------------------------------------------------------------------
# Trampoline Tracer (shared by ELF and PE CRT startup paths)
# ---------------------------------------------------------------------------

def _get_main_from_start(func, boilerplate=None):
    """
    Walk every instruction in `func`, follow outgoing call/data references, and
    return the first referenced function that is NOT in the boilerplate set.

    Used to trace:
      ELF:  _start → __libc_start_main(main, …)   → returns main
      PE:   _mainCRTStartup → main(…)              → returns main
    """
    from ghidra.program.flatapi import FlatProgramAPI

    prog     = func.getProgram()
    flatapi  = FlatProgramAPI(prog)
    ref_mgr  = prog.getReferenceManager()
    sym_tbl  = prog.getSymbolTable()
    f_mgr    = prog.getFunctionManager()

    if boilerplate is None:
        fmt       = get_binary_format(prog)
        boilerplate = get_startup_boilerplate_set(fmt)

    func_body = func.getBody()
    iterator  = func_body.getAddresses(True)
    while iterator.hasNext():
        addr = iterator.next()
        for ref in ref_mgr.getReferencesFrom(addr):
            to_addr      = ref.getToAddress()
            ref_type     = ref.getReferenceType()
            target_sym   = sym_tbl.getPrimarySymbol(to_addr)
            target_name  = target_sym.getName() if target_sym else "UNKNOWN"

            target_func = f_mgr.getFunctionAt(to_addr)
            if target_func:
                name = target_func.getName()
                if name not in boilerplate:
                    return target_func
            elif ref_type.isData() and target_name not in (boilerplate | {"UNKNOWN", "No Symbol"}):
                return flatapi.getFunction(target_name)

    return None


# ---------------------------------------------------------------------------
# Format-specific helpers
# ---------------------------------------------------------------------------

def _find_main_elf(coreFunctions, program):
    """
    ELF strategy chain (Linux / bare ELF):
      1. 'main'  — present in stripped binary with debug info left
      2. 'entry' — traces through __libc_start_main if found
      3. 'start' — always traces (ELF _start trampoline)
      4. Recorded ELF entry-point address
    """
    from ghidra.util.task import ConsoleTaskMonitor
    boilerplate = get_startup_boilerplate_set("ELF")

    # Strategy 1: Explicit 'main'
    if "main" in coreFunctions:
        print("    -> [ELF] Found 'main' directly in .text")
        return coreFunctions["main"]

    # Strategy 2: 'entry' that calls __libc_start_main
    if "entry" in coreFunctions:
        candidate    = coreFunctions["entry"]
        called_names = [f.getName() for f in candidate.getCalledFunctions(ConsoleTaskMonitor())]
        if "__libc_start_main" in called_names:
            traced = _get_main_from_start(candidate, boilerplate)
            if traced:
                print(f"    -> [ELF] 'entry' calls __libc_start_main, traced: {traced.getName()}")
                return traced
        print("    -> [ELF] Found 'entry' directly")
        return candidate

    # Strategy 3: '_start' / 'start' trampoline
    for start_name in ("_start", "start"):
        if start_name in coreFunctions:
            result = _get_main_from_start(coreFunctions[start_name], boilerplate)
            if result:
                print(f"    -> [ELF] '{start_name}' traced to: {result.getName()}")
                return result

    # Strategy 4: Recorded ELF entry-point address
    entry_addrs = program.getSymbolTable().getExternalEntryPointIterator()
    fm = program.getFunctionManager()
    while entry_addrs.hasNext():
        addr = entry_addrs.next()
        func = fm.getFunctionAt(addr)
        if func and func.getName() in coreFunctions:
            candidate    = coreFunctions[func.getName()]
            called_names = [f.getName() for f in candidate.getCalledFunctions(ConsoleTaskMonitor())]
            if "__libc_start_main" in called_names or func.getName() in ("start", "_start"):
                traced = _get_main_from_start(candidate, boilerplate)
                if traced:
                    print(f"    -> [ELF] Entry '{func.getName()}' is boilerplate, traced: {traced.getName()}")
                    return traced
            print(f"    -> [ELF] Using entry point function directly: {func.getName()}")
            return candidate

    return None


def _find_main_macho(coreFunctions, program):
    """
    Mach-O strategy chain (macOS ARM64 / x86-64):
      1. 'main'  — debug builds may leave the symbol unmangled
      2. '_main' — clang always emits an underscore prefix at the symbol level;
                   Ghidra strips it in most cases but keeps it in some loaders
      3. LC_MAIN entry-point address — dyld calls the real main directly, no
                                       trampoline, so just resolve the function
                                       at the recorded entry address
      4. BFS fallback — any non-boilerplate function reachable from the entry
    """
    boilerplate = get_startup_boilerplate_set("MACHO")
    fm          = program.getFunctionManager()

    # Strategy 1: unmangled 'main'
    if "main" in coreFunctions:
        print("    -> [Mach-O] Found 'main' directly")
        return coreFunctions["main"]

    # Strategy 2: clang underscore-prefixed '_main'
    if "_main" in coreFunctions:
        print("    -> [Mach-O] Found '_main' (clang underscore prefix)")
        return coreFunctions["_main"]

    # Strategy 3: LC_MAIN / recorded entry point — dyld → _main directly
    entry_addrs = program.getSymbolTable().getExternalEntryPointIterator()
    while entry_addrs.hasNext():
        addr = entry_addrs.next()
        func = fm.getFunctionAt(addr)
        if func:
            name = func.getName()
            # If the entry is not boilerplate itself, use it directly
            if name not in boilerplate and name in coreFunctions:
                print(f"    -> [Mach-O] Entry point is real main: {name}")
                return coreFunctions[name]
            # Otherwise trace one level (rare — some thin wrappers exist)
            traced = _get_main_from_start(func, boilerplate)
            if traced and traced.getName() in coreFunctions:
                print(f"    -> [Mach-O] Entry point traced to: {traced.getName()}")
                return coreFunctions[traced.getName()]

    # Strategy 4: fall back to highest-instruction-count non-boilerplate function
    # (best heuristic when symbol table is fully stripped)
    best = None
    best_size = 0
    for name, f in coreFunctions.items():
        if name in boilerplate:
            continue
        size = f.getBody().getNumAddresses()
        if size > best_size:
            best_size = size
            best = f
    if best:
        print(f"    -> [Mach-O] Fallback: largest non-boilerplate function: {best.getName()}")
        return best

    return None


def _find_main_pe(coreFunctions, program):
    """
    PE strategy chain (Windows x86 / x86-64):
      1. 'main', 'wmain'              — console applications
      2. 'WinMain', 'wWinMain'        — GUI applications
      3. 'DllMain'                    — dynamic-link libraries
      4. CRT startup trampoline trace — _mainCRTStartup → main
      5. Recorded PE AddressOfEntryPoint
    """
    from ghidra.util.task import ConsoleTaskMonitor
    boilerplate = get_startup_boilerplate_set("PE")
    fm          = program.getFunctionManager()

    # Strategy 1 & 2: known main variants
    for candidate_name in ("main", "wmain", "WinMain", "wWinMain", "DllMain"):
        if candidate_name in coreFunctions:
            print(f"    -> [PE] Found '{candidate_name}' directly")
            return coreFunctions[candidate_name]

    # Strategy 3: CRT startup trampoline → main
    for crt_name in ("_mainCRTStartup", "WinMainCRTStartup", "__scrt_common_main",
                     "__tmainCRTStartup", "__mainCRTStartup"):
        if crt_name in coreFunctions:
            traced = _get_main_from_start(coreFunctions[crt_name], boilerplate)
            if traced and traced.getName() in coreFunctions:
                print(f"    -> [PE] '{crt_name}' traced to: {traced.getName()}")
                return coreFunctions[traced.getName()]

    # Strategy 4: Recorded PE entry-point address
    entry_addrs = program.getSymbolTable().getExternalEntryPointIterator()
    while entry_addrs.hasNext():
        addr = entry_addrs.next()
        func = fm.getFunctionAt(addr)
        if func and func.getName() in coreFunctions:
            candidate    = coreFunctions[func.getName()]
            called_names = [f.getName() for f in candidate.getCalledFunctions(ConsoleTaskMonitor())]
            if any(n in boilerplate for n in called_names):
                traced = _get_main_from_start(candidate, boilerplate)
                if traced and traced.getName() in coreFunctions:
                    print(f"    -> [PE] Entry traced to: {traced.getName()}")
                    return coreFunctions[traced.getName()]
            print(f"    -> [PE] Using entry point: {func.getName()}")
            return candidate

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_main(coreFunctions, program):
    """
    Locate the application's true entry function using a format-aware strategy
    chain.  Supports ELF (Linux), Mach-O (macOS), and PE (Windows).

    Parameters
    ----------
    coreFunctions : dict[str, Function]
        All user-defined code-section functions, keyed by name.
    program : ghidra.program.model.listing.Program
        Active Ghidra program.

    Returns
    -------
    Function | None
    """
    fmt = get_binary_format(program)
    print(f"    -> [find_main] Detected format: {fmt}")

    if fmt == "MACHO":
        result = _find_main_macho(coreFunctions, program)
    elif fmt == "PE":
        result = _find_main_pe(coreFunctions, program)
    else:
        # ELF or UNKNOWN — fall back to ELF strategy
        result = _find_main_elf(coreFunctions, program)

    if result is None:
        print("    -> [ERROR] Could not locate main / entry function")
    return result
