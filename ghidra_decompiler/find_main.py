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

    1. If 'start' exists, trace its __libc_start_main argument.
    2. If a function named 'entry' or 'main' exists:
       - If it calls __libc_start_main internally, treat it as start and trace main.
       - Otherwise return it directly as main.
    3. Fall back to the function at the program's recorded entry point address.

    Parameters
    ----------
    coreFunctions : dict[str, Function]
        All user-defined .text functions keyed by name.
    program : ghidra.program.model.listing.Program

    Returns
    -------
    Function | None
    """
    # Strategy 1: start -> __libc_start_main -> main
    if "start" in coreFunctions:
        result = _get_main_from_start(coreFunctions["start"])
        if result:
            return result

    # Strategy 2: function literally named 'main' or 'entry' in .text
    for candidate_name in ("main", "entry"):
        if candidate_name in coreFunctions:
            candidate = coreFunctions[candidate_name]
            # Check if this function acts like a _start (calls __libc_start_main)
            traced = _get_main_from_start(candidate)
            if traced:
                print(f"    -> [FALLBACK] '{candidate_name}' is a _start-like function, "
                      f"traced real main: {traced.getName()}")
                return traced
            else:
                print(f"    -> [FALLBACK] Found '{candidate_name}' directly in .text")
                return candidate

    # Strategy 3: function at the program's recorded entry point address
    entry_addrs = program.getSymbolTable().getExternalEntryPointIterator()
    fm = program.getFunctionManager()
    while entry_addrs.hasNext():
        addr = entry_addrs.next()
        func = fm.getFunctionAt(addr)
        if func and func.getName() in coreFunctions:
            traced = _get_main_from_start(coreFunctions[func.getName()])
            if traced:
                print(f"    -> [FALLBACK] Entry point '{func.getName()}' is _start-like, "
                      f"traced main: {traced.getName()}")
                return traced
            print(f"    -> [FALLBACK] Found entry point function: {func.getName()}")
            return coreFunctions[func.getName()]

    print("    -> [ERROR] Could not find main function")
    return None
