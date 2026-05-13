"""
ghidra_decompiler.gui_utils
---------------------------
Optional extensions and advanced utilities tailored specifically for live
Ghidra GUI sessions. Contains programmatic P-Code transforms, HighVariable
splitting logic, and database view synchronizers.
"""

from .optimizer import optimize_gui_function_variables

__all__ = ["optimize_gui_function_variables"]
