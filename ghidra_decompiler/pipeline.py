"""
ghidra_decompiler.pipeline
---------------------------
Top-level orchestrator for the AI-enhanced decompilation pipeline.

Classes
-------
    DecompilerPipeline
        Encapsulates the full decompilation state and orchestration.

Public API (Wrappers)
---------------------
    enhance_decompilation_with_ai(program, iface, core_funcs,
                                  skip_ai_for_funcs=None, model="openrouter/free")
        -> dict[str, dict]   (stored suggestions keyed by function name)
"""

from ghidra_decompiler.semantics import (
    update_function_semantics, apply_openrouter_suggestions, finalize_main_signature
)
from ghidra_decompiler.alignment import align_usage_with_called_functions
from ghidra_decompiler.ai.openrouter import get_openrouter_suggestions


class DecompilerPipeline:
    """
    Stateful orchestrator for the AI-enhanced decompilation process.
    """

    def __init__(self, program, iface, core_funcs, model="openrouter/free"):
        self.program = program
        self.iface = iface
        self.core_funcs = core_funcs
        self.model = model
        self.stored_suggestions = {}
        self.global_context_c = None

    def _get_monitor(self):
        from ghidra.util.task import ConsoleTaskMonitor
        return ConsoleTaskMonitor()

    def capture_global_context(self):
        """
        Identify 'main' or entry point to use as global reference context for AI consistency.
        """
        main_func = self.core_funcs.get("main")
        if not main_func and self.core_funcs:
            main_func = next(iter(self.core_funcs.values()))

        if main_func:
            print(f"[Context] Using '{main_func.getName()}' as global reference for AI consistency.")
            m_results = self.iface.decompileFunction(main_func, 30, self._get_monitor())
            if m_results.decompileCompleted():
                self.global_context_c = m_results.getDecompiledFunction().getC()

    def run_semantic_and_ai_pass(self, skip_ai_for_funcs=None, clear_cache=False):
        """
        Pass 1: Setup basic semantics, extract referenced string literals, and dispatch
        parallelized LLM requests to gather rich semantic suggestions.
        """
        import re
        from concurrent.futures import ThreadPoolExecutor, as_completed

        if skip_ai_for_funcs is None:
            skip_ai_for_funcs = []

        # Step A: Sequentially collect ASTs, context snippets, and string literals
        # to guarantee strict thread-safety against Ghidra's DecompInterface service.
        tasks_payloads = []
        for name, func in self.core_funcs.items():
            # Update semantics (return type, param commit) via native Ghidra analysis
            update_function_semantics(self.program, func, name)

            if name not in skip_ai_for_funcs:
                dec_results = self.iface.decompileFunction(func, 30, self._get_monitor())
                if dec_results.decompileCompleted():
                    initial_c = dec_results.getDecompiledFunction().getC()

                    # Extract string literals mapped inside double quotes as primary contextual references
                    literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', initial_c)
                    
                    # Collect caller snippets
                    caller_snippets = []
                    for caller in func.getCallingFunctions(self._get_monitor()):
                        if caller.getName() in self.core_funcs:
                            r = self.iface.decompileFunction(caller, 30, self._get_monitor())
                            if r.decompileCompleted():
                                caller_snippets.append((caller.getName(), r.getDecompiledFunction().getC()))

                    # Collect callee snippets
                    callee_snippets = []
                    for callee in func.getCalledFunctions(self._get_monitor()):
                        if callee.getName() in self.core_funcs:
                            r = self.iface.decompileFunction(callee, 30, self._get_monitor())
                            if r.decompileCompleted():
                                callee_snippets.append((callee.getName(), r.getDecompiledFunction().getC()))

                    tasks_payloads.append({
                        "name": name,
                        "decompiled_c": initial_c,
                        "context_c": self.global_context_c,
                        "caller_snippets": caller_snippets or None,
                        "callee_snippets": callee_snippets or None,
                        "string_literals": literals or None
                    })

        # Step B: Execute OpenRouter queries asynchronously across fully parallelized threads
        if tasks_payloads:
            print(f"\n[Pipeline] Dispatching {len(tasks_payloads)} asynchronous LLM requests in parallel...")
            max_workers = min(4, len(tasks_payloads)) # Safely bounded concurrency pool
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Map futures to their function identifiers
                future_to_name = {
                    executor.submit(
                        get_openrouter_suggestions,
                        p["decompiled_c"],
                        model=self.model,
                        context_c=p["context_c"],
                        caller_snippets=p["caller_snippets"],
                        callee_snippets=p["callee_snippets"],
                        string_literals=p["string_literals"],
                        clear_cache=clear_cache
                    ): p["name"] for p in tasks_payloads
                }

                for future in as_completed(future_to_name):
                    func_name = future_to_name[future]
                    try:
                        suggestions = future.result()
                        if suggestions and any(suggestions.get(k) for k in ("variables", "parameters", "function_name", "context", "custom_types")):
                            if not suggestions.get("function_name"):
                                print(f"[OpenRouter] WARNING: No function_name in suggestions for '{func_name}', storing partial results.")
                            self.stored_suggestions[func_name] = suggestions
                            print(f"[OpenRouter] Successfully mapped suggestions for '{func_name}'.")
                        else:
                            print(f"[OpenRouter] WARNING: Empty/unusable suggestions returned for '{func_name}'. Skipping.")
                    except Exception as e:
                        import traceback
                        print(f"[OpenRouter] Future execution exception for '{func_name}': {e}")
                        traceback.print_exc()

    def apply_suggestions(self):
        """
        Pass 2: Apply all LLM suggestions (function names, variables, parameters).
        """
        for name, func in self.core_funcs.items():
            if name in self.stored_suggestions:
                apply_openrouter_suggestions(self.program, func, self.stored_suggestions[name])

    def run_alignment_passes(self, num_passes=2):
        """
        Passes 3 & 4: Deep alignment (ensures names propagate multiple levels deep).
        """
        for pass_num in range(1, num_passes + 1):
            print(f"[Alignment] Starting global alignment pass {pass_num}/{num_passes} ...")
            for name, func in self.core_funcs.items():
                dec_results = self.iface.decompileFunction(func, 30, self._get_monitor())
                if dec_results.decompileCompleted():
                    aligned_c = dec_results.getDecompiledFunction().getC()
                    align_usage_with_called_functions(
                        self.program, func, aligned_c, self.core_funcs.values()
                    )

    def execute_full_pipeline(self, skip_ai_for_funcs=None, clear_cache=False):
        """
        Run the complete pipeline from start to finish.
        """
        self.capture_global_context()
        self.run_semantic_and_ai_pass(skip_ai_for_funcs=skip_ai_for_funcs, clear_cache=clear_cache)
        
        # Collect, sanitize and register all custom types
        all_custom_types = []
        for suggestions in self.stored_suggestions.values():
            if isinstance(suggestions, dict) and "custom_types" in suggestions:
                all_custom_types.extend(suggestions["custom_types"])
        if all_custom_types:
            try:
                from ghidra_decompiler.custom_types import sanitize_custom_types, register_custom_datatypes
                sanitized_types = sanitize_custom_types(all_custom_types)
                register_custom_datatypes(self.program, sanitized_types)
            except Exception as cte:
                print(f"[Pipeline] WARNING: Could not register custom types: {cte}")

        self.apply_suggestions()
        self.run_alignment_passes()
        
        # Final cleanup for main signature if it was not already canonicalized
        main_func = self.core_funcs.get("main")
        if main_func:
            finalize_main_signature(self.program, main_func)

        return self.stored_suggestions


def enhance_decompilation_with_ai(
    program,
    iface,
    core_funcs,
    skip_ai_for_funcs=None,
    model="openrouter/free",
):
    """
    Functional wrapper around DecompilerPipeline for backward compatibility.
    """
    pipeline = DecompilerPipeline(program, iface, core_funcs, model=model)
    return pipeline.execute_full_pipeline(skip_ai_for_funcs=skip_ai_for_funcs)
