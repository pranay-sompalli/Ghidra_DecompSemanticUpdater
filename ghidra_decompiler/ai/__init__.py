"""
ghidra_decompiler.ai
====================
Sub-package for AI/LLM integrations used by the decompilation pipeline.

Currently supported backends
-----------------------------
    cerebras  — Cerebras Cloud API (llama3.1-8b, qwen-3-235b, gpt-oss-120b)
"""

from ghidra_decompiler.ai.cerebras import get_cerebras_suggestions

__all__ = ["get_cerebras_suggestions"]
