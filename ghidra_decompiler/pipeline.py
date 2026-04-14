"""
ghidra_decompiler.pipeline
---------------------------
Top-level orchestrator for the AI-enhanced decompilation pipeline.

Public API
----------
    enhance_decompilation_with_ai(program, iface, core_funcs,
                                  skip_ai_for_funcs=None, model="llama3.1-8b")
        -> dict[str, dict]   (stored suggestions keyed by function name)
"""

from ghidra_decompiler.semantics import update_function_semantics, apply_cerebras_suggestions
from ghidra_decompiler.alignment import align_usage_with_called_functions
from ghidra_decompiler.ai.cerebras import get_cerebras_suggestions


def enhance_decompilation_with_ai(
    program,
    iface,
    core_funcs,
    skip_ai_for_funcs=None,
    model="llama3.1-8b",
):
    """
    Coordinate the full pipeline of semantic updates, AI variable/name suggestions,
    and intelligent parameter propagation.

    Parameters
    ----------
    program           : ghidra.program.model.listing.Program
    iface             : ghidra.app.decompiler.DecompInterface
    core_funcs        : dict
        Mapping of { "function_name": FunctionObject } indicating which functions to process.
    skip_ai_for_funcs : list[str], optional
        Function names that should bypass AI querying (e.g., 'main' because it has a
        known standard signature).
    model : str
        The Cerebras model ID to use (default: "llama3.1-8b").

    Returns
    -------
    dict[str, dict]
        Stored suggestions keyed by function name, for use in the final output pass.
    """
    from ghidra.util.task import ConsoleTaskMonitor

    if skip_ai_for_funcs is None:
        skip_ai_for_funcs = []

    # Pre-Pass: Identify 'main' or entry point to use as global reference context
    global_context_c = None
    main_func = core_funcs.get("main")
    if not main_func:
        # Fallback to the first function in core_funcs if 'main' isn't explicitly named
        main_func = next(iter(core_funcs.values())) if core_funcs else None

    if main_func:
        print(f"[Context] Using '{main_func.getName()}' as global reference for AI consistency.")
        m_results = iface.decompileFunction(main_func, 30, ConsoleTaskMonitor())
        if m_results.decompileCompleted():
            global_context_c = m_results.getDecompiledFunction().getC()

    # Pass 1: Setup basic semantics and gather LLM suggestions
    stored_suggestions = {}
    for name, func in core_funcs.items():
        # Update semantics (return type, param commit) via Ghidra analysis
        update_function_semantics(program, func, name)

        if name not in skip_ai_for_funcs:
            print(f"[Cerebras] Requesting suggestions for '{name}' ...")
            dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
            if dec_results.decompileCompleted():
                initial_c = dec_results.getDecompiledFunction().getC()
                suggestions = get_cerebras_suggestions(initial_c, model=model, context_c=global_context_c)
                if suggestions:
                    stored_suggestions[name] = suggestions

    # Pass 2: Apply all LLM suggestions (function names, variables, parameters)
    for name, func in core_funcs.items():
        if name in stored_suggestions:
            apply_cerebras_suggestions(program, func, stored_suggestions[name])

    # Passes 3 & 4: Deep alignment (two passes ensure names propagate multiple levels deep)
    for pass_num in [1, 2]:
        print(f"[Alignment] Starting global alignment pass {pass_num}/2 ...")
        for name, func in core_funcs.items():
            dec_results = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
            if dec_results.decompileCompleted():
                aligned_c = dec_results.getDecompiledFunction().getC()
                align_usage_with_called_functions(program, func, aligned_c, core_funcs.values())

    return stored_suggestions
