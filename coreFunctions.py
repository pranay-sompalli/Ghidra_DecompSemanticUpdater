from findMain import find_main

def _get_outgoing_funcs(func, coreFunctions):
    """
    Return Function objects called by `func` that are in coreFunctions
    (i.e., user-defined .text functions). Library/external calls are
    automatically excluded since they won't be in the dict.
    """
    from ghidra.util.task import ConsoleTaskMonitor
    
    called = func.getCalledFunctions(ConsoleTaskMonitor())
    return [coreFunctions[cf.getName()] for cf in called if cf.getName() in coreFunctions]

def getCoreFunctions(coreFunctions, program=None):
    """
    Starting from main (found via find_main), BFS through all outgoing calls
    to collect every reachable user-defined function.
    """
    filteredFunctions = {}

    # Step 1: Find main using the priority chain
    main_func = find_main(coreFunctions, program)
    if not main_func:
        return filteredFunctions

    # Step 2: BFS from main, only following functions in coreFunctions
    queue = [main_func]
    visited = set()
    filteredFunctions["main"] = main_func

    while queue:
        func = queue.pop(0)
        name = func.getName()
        if name in visited:
            continue
        visited.add(name)
        if func != main_func:
            filteredFunctions[name] = func

        for callee in _get_outgoing_funcs(func, coreFunctions):
            if callee.getName() not in visited:
                queue.append(callee)

    return filteredFunctions