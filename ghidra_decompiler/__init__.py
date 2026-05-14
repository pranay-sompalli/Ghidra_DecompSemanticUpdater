"""
ghidra_decompiler
=================
A Python package for automating Ghidra decompilation with AI-driven semantic
improvements via the OpenRouter API.

Public API
----------
    from ghidra_decompiler import enhance_decompilation_with_ai
    from ghidra_decompiler import sanitize_c_code, strip_leading_underscores
"""

from ghidra_decompiler.pipeline import enhance_decompilation_with_ai, DecompilerPipeline
from ghidra_decompiler.semantics import (
    strip_leading_underscores,
    update_function_semantics,
    update_variable_names_and_types,
    change_function_name,
    change_function_parameters,
    apply_openrouter_suggestions,
)
from ghidra_decompiler.code_utils import sanitize_c_code, is_generic_name, clean_c_argument
from ghidra_decompiler.type_utils import resolve_type, is_array_type, is_pointer_type
from ghidra_decompiler.alignment import align_usage_with_called_functions
from ghidra_decompiler.core_functions import getCoreFunctions
from ghidra_decompiler.find_main import find_main
from ghidra_decompiler.platform_utils import (
    get_binary_format,
    get_architecture,
    get_text_section_names,
    get_data_section_names,
    get_linker_noise_symbols,
    get_boilerplate_pattern,
    get_calling_convention_tokens,
    get_ghidra_type_map,
    describe_platform,
)

__all__ = [
    "enhance_decompilation_with_ai",
    "DecompilerPipeline",
    "strip_leading_underscores",
    "update_function_semantics",
    "update_variable_names_and_types",
    "change_function_name",
    "change_function_parameters",
    "apply_openrouter_suggestions",
    "sanitize_c_code",
    "is_generic_name",
    "clean_c_argument",
    "resolve_type",
    "is_array_type",
    "is_pointer_type",
    "align_usage_with_called_functions",
    "getCoreFunctions",
    "find_main",
    # Platform utilities
    "get_binary_format",
    "get_architecture",
    "get_text_section_names",
    "get_data_section_names",
    "get_linker_noise_symbols",
    "get_boilerplate_pattern",
    "get_calling_convention_tokens",
    "get_ghidra_type_map",
    "describe_platform",
]
