def getMain(func):

    from ghidra.program.flatapi import FlatProgramAPI

    prog = func.getProgram()

    flatapi=FlatProgramAPI(prog)

    ref_manager = prog.getReferenceManager()
    symbol_table = prog.getSymbolTable()
    f_manager = prog.getFunctionManager()

    funcBody = func.getBody()
    
    # Iterate through every address in the function's range
    iterator = funcBody.getAddresses(True)
    while iterator.hasNext():
        addr = iterator.next()
        
        # Get all references originating from this specific address
        for ref in ref_manager.getReferencesFrom(addr):
            to_addr = ref.getToAddress()
            ref_type = ref.getReferenceType()
            
            # Identify what is at the destination (Function name, label, etc.)
            target_symbol = symbol_table.getPrimarySymbol(to_addr)
            target_name = target_symbol.getName() if target_symbol else "No Symbol"
            
            # We are looking for something that is a function but not standard libc boilerplate
            target_func = f_manager.getFunctionAt(to_addr)
            if target_func:
                name = target_func.getName()
                if name not in ["__libc_start_main", "UNKNOWN", "_init", "_fini", "start", "__libc_csu_init", "__libc_csu_fini"]:
                    return target_func
                    
            # Sometimes main is not recognized as a Function object yet, but as a Data reference
            elif ref_type.isData() and target_name not in ["No Symbol", "__libc_start_main", "UNKNOWN", "_init", "_fini", "start", "__libc_csu_init", "__libc_csu_fini"]:
                return flatapi.getFunction(target_name)
                
    return None


def find_main(coreFunctions, program):
    """
    Locate the main function using a priority chain of strategies:
    1. If 'start' exists, trace its __libc_start_main argument (via getMain)
    2. If a function named 'entry' or 'main' exists:
       - If it calls __libc_start_main internally, treat it as start and trace main via getMain
       - Otherwise return it directly as main
    3. Fall back to the function at the program's entry point address
    """
    # Strategy 1: start -> __libc_start_main -> main
    if "start" in coreFunctions:
        result = getMain(coreFunctions["start"])
        if result:
            return result

    # Strategy 2: function literally named 'main' or 'entry' in .text
    for candidate_name in ("main", "entry"):
        if candidate_name in coreFunctions:
            candidate = coreFunctions[candidate_name]
            # Check if this function acts like a _start (calls __libc_start_main)
            # by trying to trace main through it
            traced = getMain(candidate)
            if traced:
                print(f"    -> [FALLBACK] '{candidate_name}' is a _start-like function, traced real main: {traced.getName()}")
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
            # Same check — is it a _start or a real main?
            traced = getMain(coreFunctions[func.getName()])
            if traced:
                print(f"    -> [FALLBACK] Entry point '{func.getName()}' is _start-like, traced main: {traced.getName()}")
                return traced
            print(f"    -> [FALLBACK] Found entry point function: {func.getName()}")
            return coreFunctions[func.getName()]

    print("    -> [ERROR] Could not find main function")
    return None