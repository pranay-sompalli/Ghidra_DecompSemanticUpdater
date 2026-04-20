"""
ghidra_decompiler.find_main
-----------------------------
Strategies for locating the true `main` entry point inside a Ghidra program,
even when the binary uses a libc startup trampoline (start / entry).

Public API
----------
    find_main(coreFunctions, program) -> Function | None
"""


def _get_main_from_start(func):
    """
    Scan every address in `func` for the first outgoing call/data-reference that
    is NOT a well-known libc boilerplate symbol.  This traces _start ->
    __libc_start_main -> main.
    """
    from ghidra.program.flatapi import FlatProgramAPI

    prog = func.getProgram()
    flatapi = FlatProgramAPI(prog)

    ref_manager  = prog.getReferenceManager()
    symbol_table = prog.getSymbolTable()
    f_manager    = prog.getFunctionManager()

    _BOILERPLATE = frozenset({
        "__libc_start_main", "UNKNOWN", "_init", "_fini",
        "start", "__libc_csu_init", "__libc_csu_fini",
    })

    func_body = func.getBody()
    iterator  = func_body.getAddresses(True)
    while iterator.hasNext():
        addr = iterator.next()
        for ref in ref_manager.getReferencesFrom(addr):
            to_addr     = ref.getToAddress()
            ref_type    = ref.getReferenceType()

            target_symbol = symbol_table.getPrimarySymbol(to_addr)
            target_name   = target_symbol.getName() if target_symbol else "No Symbol"

            target_func = f_manager.getFunctionAt(to_addr)
            if target_func:
                name = target_func.getName()
                if name not in _BOILERPLATE:
                    return target_func
            # Sometimes main is not yet a Function object but a Data reference
            elif ref_type.isData() and target_name not in (_BOILERPLATE | {"No Symbol"}):
                return flatapi.getFunction(target_name)

    return None


def find_main(coreFunctions, program):
    """
    Locate the main function using a priority chain of strategies:

    1. If 'main' exists in coreFunctions, return it directly.
    2. If 'entry' exists, return it unless it explicitly calls __libc_start_main.
    3. If 'start' exists, trace its __libc_start_main argument.
    4. Fall back to the function at the program's recorded entry point address.

    Parameters
    ----------
    coreFunctions : dict[str, Function]
        All user-defined .text functions keyed by name.
    program : ghidra.program.model.listing.Program

    Returns
    -------
    Function | None
    """
    from ghidra.util.task import ConsoleTaskMonitor

    # Strategy 1: Explicit 'main'
    if "main" in coreFunctions:
        print("    -> [Strategy] Found 'main' directly in .text")
        return coreFunctions["main"]

    # Strategy 2: 'entry' (trace only if it looks like a libc startup trampoline)
    if "entry" in coreFunctions:
        candidate = coreFunctions["entry"]
        called_names = [f.getName() for f in candidate.getCalledFunctions(ConsoleTaskMonitor())]
        if "__libc_start_main" in called_names:
            traced = _get_main_from_start(candidate)
            if traced:
                print(f"    -> [Strategy] 'entry' calls __libc_start_main, traced real main: {traced.getName()}")
                return traced
        
        print("    -> [Strategy] Found 'entry' directly in .text")
        return candidate

    # Strategy 3: 'start' -> usually boilerplate, always trace
    if "start" in coreFunctions:
        result = _get_main_from_start(coreFunctions["start"])
        if result:
            print(f"    -> [Strategy] 'start' detected, traced real main: {result.getName()}")
            return result

    # Strategy 4: function at the program's recorded entry point address
    entry_addrs = program.getSymbolTable().getExternalEntryPointIterator()
    fm = program.getFunctionManager()
    while entry_addrs.hasNext():
        addr = entry_addrs.next()
        func = fm.getFunctionAt(addr)
        if func and func.getName() in coreFunctions:
            candidate = coreFunctions[func.getName()]
            called_names = [f.getName() for f in candidate.getCalledFunctions(ConsoleTaskMonitor())]
            if "__libc_start_main" in called_names or func.getName() == "start":
                traced = _get_main_from_start(candidate)
                if traced:
                    print(f"    -> [Strategy] Entry point '{func.getName()}' is boilerplate, "
                          f"traced main: {traced.getName()}")
                    return traced
            
            print(f"    -> [Strategy] Using entry point function directly: {func.getName()}")
            return candidate

    print("    -> [ERROR] Could not find main function")
    return None
