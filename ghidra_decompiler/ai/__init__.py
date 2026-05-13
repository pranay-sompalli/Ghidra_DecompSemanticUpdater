"""
ghidra_decompiler.ai
====================
Sub-package for AI/LLM integrations used by the decompilation pipeline.

Currently supported backends
-----------------------------
    openrouter — OpenRouter API (llama-3.1-8b-instruct, qwen-2.5-72b-instruct, claude-3.5-sonnet)
"""

from ghidra_decompiler.ai.openrouter import get_openrouter_suggestions

__all__ = ["get_openrouter_suggestions"]
