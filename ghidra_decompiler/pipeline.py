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
                                  skip_ai_for_funcs=None, model="llama3.1-8b")
        -> dict[str, dict]   (stored suggestions keyed by function name)
"""

from ghidra_decompiler.semantics import update_function_semantics, apply_cerebras_suggestions
from ghidra_decompiler.alignment import align_usage_with_called_functions
from ghidra_decompiler.ai.cerebras import get_cerebras_suggestions


class DecompilerPipeline:
    """
    Stateful orchestrator for the AI-enhanced decompilation process.
    """

    def __init__(self, program, iface, core_funcs, model="llama3.1-8b"):
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

    def run_semantic_and_ai_pass(self, skip_ai_for_funcs=None):
        """
        Pass 1: Setup basic semantics and gather LLM suggestions.
        """
        if skip_ai_for_funcs is None:
            skip_ai_for_funcs = []

        for name, func in self.core_funcs.items():
            # Update semantics (return type, param commit) via Ghidra analysis
            update_function_semantics(self.program, func, name)

            if name not in skip_ai_for_funcs:
                print(f"[Cerebras] Requesting suggestions for '{name}' ...")
                dec_results = self.iface.decompileFunction(func, 30, self._get_monitor())
                if dec_results.decompileCompleted():
                    initial_c = dec_results.getDecompiledFunction().getC()
                    suggestions = get_cerebras_suggestions(
                        initial_c, model=self.model, context_c=self.global_context_c
                    )
                    if suggestions:
                        self.stored_suggestions[name] = suggestions

    def apply_suggestions(self):
        """
        Pass 2: Apply all LLM suggestions (function names, variables, parameters).
        """
        for name, func in self.core_funcs.items():
            if name in self.stored_suggestions:
                apply_cerebras_suggestions(self.program, func, self.stored_suggestions[name])

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

    def execute_full_pipeline(self, skip_ai_for_funcs=None):
        """
        Run the complete pipeline from start to finish.
        """
        self.capture_global_context()
        self.run_semantic_and_ai_pass(skip_ai_for_funcs=skip_ai_for_funcs)
        self.apply_suggestions()
        self.run_alignment_passes()
        return self.stored_suggestions


def enhance_decompilation_with_ai(
    program,
    iface,
    core_funcs,
    skip_ai_for_funcs=None,
    model="llama3.1-8b",
):
    """
    Functional wrapper around DecompilerPipeline for backward compatibility.
    """
    pipeline = DecompilerPipeline(program, iface, core_funcs, model=model)
    return pipeline.execute_full_pipeline(skip_ai_for_funcs=skip_ai_for_funcs)
