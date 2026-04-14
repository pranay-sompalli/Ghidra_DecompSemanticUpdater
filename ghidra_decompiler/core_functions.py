"""
ghidra_decompiler.core_functions
---------------------------------
Utilities for collecting the set of user-defined .text functions reachable
from main via BFS.

Public API
----------
    getCoreFunctions(coreFunctions, program=None) -> dict[str, Function]
"""

from ghidra_decompiler.find_main import find_main


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

    Parameters
    ----------
    coreFunctions : dict[str, Function]
        All .text functions keyed by name (typically filtered by section).
    program : ghidra.program.model.listing.Program, optional
        Required only when find_main needs to probe the entry-point symbol table.

    Returns
    -------
    dict[str, Function]
        Subset of coreFunctions reachable from main, with "main" always first.
    """
    filtered = {}

    main_func = find_main(coreFunctions, program)
    if not main_func:
        return filtered

    queue   = [main_func]
    visited = set()
    filtered["main"] = main_func

    while queue:
        func = queue.pop(0)
        name = func.getName()
        if name in visited:
            continue
        visited.add(name)
        if func != main_func:
            filtered[name] = func

        for callee in _get_outgoing_funcs(func, coreFunctions):
            if callee.getName() not in visited:
                queue.append(callee)

    return filtered
