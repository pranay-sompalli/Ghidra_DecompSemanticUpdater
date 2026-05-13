"""
ghidra_decompiler.ai
====================
Sub-package for AI/LLM integrations used by the decompilation pipeline.

Currently supported backends
-----------------------------
    openrouter — OpenRouter API (qwen3-coder:free, llama-3.3-70b-instruct:free, gpt-oss-120b:free, openrouter/free)
"""

from ghidra_decompiler.ai.openrouter import get_openrouter_suggestions

__all__ = ["get_openrouter_suggestions"]
