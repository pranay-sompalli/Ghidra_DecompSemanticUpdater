"""
ghidra_decompiler.platform_utils
---------------------------------
Binary format and CPU architecture detection utilities.

Provides format-aware constants for section names, boilerplate symbols,
linker noise, calling-convention tokens, and Ghidra type aliases so that
the pipeline works correctly across:

  Formats    : ELF (Linux), Mach-O (macOS), PE (Windows)
  Arches     : x86, x86-64, ARM32, ARM64, MIPS, RISC-V, PowerPC

Public API
----------
    get_binary_format(program)          -> 'ELF' | 'MACHO' | 'PE' | 'UNKNOWN'
    get_architecture(program)           -> 'x86' | 'x86_64' | 'ARM32' | 'ARM64' | ...
    get_text_section_names(fmt)         -> set[str]
    get_data_section_names(fmt)         -> set[str]
    get_linker_noise_symbols(fmt)       -> set[str]
    get_boilerplate_pattern(fmt)        -> re.Pattern
    get_calling_convention_tokens(arch) -> str  (regex pattern)
    get_ghidra_type_map(arch)           -> dict[str, str]
    describe_platform(program)          -> (fmt: str, arch: str)
"""

import re


# ---------------------------------------------------------------------------
# Format Detection
# ---------------------------------------------------------------------------

def get_binary_format(program):
    """
    Detect the binary format from the Ghidra program object.

    Returns
    -------
    str
        One of: 'ELF', 'MACHO', 'PE', 'UNKNOWN'
    """
    exe_format = program.getExecutableFormat()
    if exe_format is None:
        return "UNKNOWN"
    fmt_str = str(exe_format).upper()

    if "ELF" in fmt_str:
        return "ELF"
    # Ghidra reports Mach-O as "Mac OS X Mach-O" or similar
    if "MAC OS X" in fmt_str or "MACH-O" in fmt_str or "MACHO" in fmt_str:
        return "MACHO"
    # Ghidra reports PE as "Portable Executable (PE)" or "MS-DOS"
    if "PORTABLE EXECUTABLE" in fmt_str or "PE32" in fmt_str or "COFF" in fmt_str or "MS-DOS" in fmt_str:
        return "PE"

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Architecture Detection
# ---------------------------------------------------------------------------

def get_architecture(program):
    """
    Detect the CPU architecture from the Ghidra program's language.

    Returns
    -------
    str
        One of: 'x86', 'x86_64', 'ARM32', 'ARM64', 'MIPS', 'RISCV', 'PPC', 'UNKNOWN'
    """
    try:
        lang = program.getLanguage()
        proc = str(lang.getProcessor()).upper()
        # getSize() returns the address size in bits
        size = lang.getLanguageDescription().getSize()
    except Exception:
        return "UNKNOWN"

    if "X86" in proc or "386" in proc or "AMD64" in proc or "X86_64" in proc:
        return "x86_64" if size == 64 else "x86"
    if "ARM" in proc or "AARCH" in proc:
        return "ARM64" if size == 64 else "ARM32"
    if "MIPS" in proc:
        return "MIPS64" if size == 64 else "MIPS"
    if "RISC-V" in proc or "RISCV" in proc:
        return "RISCV"
    if "POWER" in proc or "PPC" in proc:
        return "PPC"

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Section Names
# ---------------------------------------------------------------------------

def get_text_section_names(fmt):
    """
    Returns the set of executable code section names expected for this format.
    Used when filtering which functions belong to user-defined code.
    """
    if fmt == "MACHO":
        # Ghidra may use the short form (__text) or the qualified form (__TEXT.__text)
        return {"__text", "__TEXT.__text"}
    if fmt == "PE":
        return {".text", "CODE", ".code"}
    # ELF (default)
    return {".text"}


def get_data_section_names(fmt):
    """
    Returns the set of data section names expected for this format.
    Used when emitting global variable declarations.
    """
    if fmt == "MACHO":
        return {
            "__data", "__bss", "__common",
            "__DATA.__data", "__DATA.__bss", "__DATA.__common",
            "__DATA_CONST.__const", "__DATA.__const",
        }
    if fmt == "PE":
        return {".data", ".rdata", ".bss", "DATA", ".idata", ".rodata"}
    # ELF (default)
    return {".data", ".bss", "__data", "__bss", "__common"}


# ---------------------------------------------------------------------------
# Linker / Runtime Noise Symbols
# ---------------------------------------------------------------------------

def get_linker_noise_symbols(fmt):
    """
    Returns the set of runtime/linker noise symbol names that should be
    excluded from the emitted C output as global declarations.
    """
    if fmt == "MACHO":
        return {
            "dyld_stub_binder", "__dyld_private", "_mh_execute_header",
            "__mod_init_func", "__mod_term_func",
        }
    if fmt == "PE":
        return {
            "__tmainCRTStartup", "__mainCRTStartup", "_WinMainCRTStartup",
            "__security_init_cookie", "_RTC_InitBase", "_RTC_Shutdown",
            "__scrt_common_main", "__scrt_common_main_seh",
            "__imp___acrt_iob_func",
        }
    # ELF (default)
    return {
        "data_start", "__data_start", "__dso_handle", "__bss_start",
        "_edata", "_end", "__libc_csu_init", "__libc_csu_fini",
        "_init", "_fini", "_start",
    }


# ---------------------------------------------------------------------------
# Boilerplate Function Filter
# ---------------------------------------------------------------------------

def get_boilerplate_pattern(fmt):
    """
    Returns a compiled regex that matches boilerplate / compiler-generated
    function names for this binary format. These are excluded from LLM processing.
    """
    if fmt == "MACHO":
        return re.compile(
            r'^(?:'
            r'__.*'                      # C++ internals (double-underscore prefix)
            r'|_GLOBAL__sub_I_.*'        # C++ static initializers
            r'|_objc_.*'                 # Objective-C runtime stubs
            r'|objc_.*'
            r'|__mod_init_func'
            r'|__mod_term_func'
            r'|dyld_stub_binder'
            r'|__dyld_private'
            r'|stub_helper'
            r'|_stub_helper'
            r'|frame_dummy'
            r')$'
        )
    if fmt == "PE":
        return re.compile(
            r'^(?:'
            r'__.*'
            r'|_.*CRTStartup'
            r'|__scrt_.*'
            r'|_RTC_.*'
            r'|__security_.*'
            r'|_mainCRTStartup'
            r'|WinMainCRTStartup'
            r'|__DllMainCRTStartup'
            r'|_amsg_exit'
            r'|__p___.*'                 # CRT internal pointers
            r')$'
        )
    # ELF (default)
    return re.compile(
        r'^(?:'
        r'_init|_fini|frame_dummy|__.*'
        r'|_GLOBAL__sub_I_.*'
        r'|__do_global_.*'
        r'|deregister_tm_clones'
        r'|register_tm_clones'
        r'|__libc_csu_.*'
        r'|_start|start'
        r')$'
    )


# ---------------------------------------------------------------------------
# Calling Convention Noise Tokens
# ---------------------------------------------------------------------------

def get_calling_convention_tokens(arch):
    """
    Returns a regex pattern string matching calling-convention noise tokens
    to strip from the final C output for this architecture.
    """
    # Common x86/Ghidra calling conventions stripped on all platforms
    _common = r'processEntry|__cdecl|__stdcall|__fastcall|__thiscall|__pascal|__vectorcall|__regcall'
    if arch in ("x86", "x86_64"):
        return r'\b(' + _common + r')\b\s*'
    if arch in ("ARM32", "ARM64"):
        return r'\b(' + _common + r'|__aapcs|__aapcs_vfp|__apcs|__arm)\b\s*'
    if arch in ("MIPS", "MIPS64"):
        return r'\b(' + _common + r'|__mips16)\b\s*'
    # Generic fallback — strip all common tokens
    return r'\b(' + _common + r')\b\s*'


# ---------------------------------------------------------------------------
# Ghidra-Specific Type Aliases
# ---------------------------------------------------------------------------

def get_ghidra_type_map(arch):
    """
    Returns a dict mapping Ghidra-specific type tokens to standard C equivalents,
    adjusted for the target architecture's pointer / register width.

    Used to emit 'typedef unsigned int uint;' etc. only when the token
    actually appears in the decompiled output.
    """
    common = {
        # 8-bit
        "undefined":  "unsigned char",
        "byte":       "unsigned char",
        "sbyte":      "signed char",
        # 16-bit
        "undefined2": "unsigned short",
        "ushort":     "unsigned short",
        "word":       "unsigned short",
        # 32-bit
        "undefined4": "unsigned int",
        "uint":       "unsigned int",
        "dword":      "unsigned int",
    }
    if arch in ("x86_64", "ARM64", "MIPS64", "RISCV", "PPC"):
        # 64-bit targets: 'ulong' maps to unsigned long long
        common["undefined8"] = "unsigned long long"
        common["ulong"]      = "unsigned long long"
        common["ulonglong"]  = "unsigned long long"
        common["longlong"]   = "long long"
        common["qword"]      = "unsigned long long"
    else:
        # 32-bit targets: 'ulong' maps to unsigned long (32-bit)
        common["ulong"]      = "unsigned long"
        common["undefined8"] = "unsigned long long"
    return common


# ---------------------------------------------------------------------------
# Entry-Point Boilerplate Sets (for find_main tracing)
# ---------------------------------------------------------------------------

def get_startup_boilerplate_set(fmt):
    """
    Returns the frozenset of function names considered startup boilerplate
    when tracing through the entry-point trampoline to find the real main.
    """
    if fmt == "MACHO":
        return frozenset({
            "dyld_stub_binder", "__dyld_private", "UNKNOWN",
            "_init", "_fini", "start",
        })
    if fmt == "PE":
        return frozenset({
            "__scrt_common_main", "__scrt_common_main_seh",
            "_mainCRTStartup", "WinMainCRTStartup", "__DllMainCRTStartup",
            "__tmainCRTStartup", "__security_init_cookie", "UNKNOWN",
        })
    # ELF
    return frozenset({
        "__libc_start_main", "UNKNOWN", "_init", "_fini",
        "start", "__libc_csu_init", "__libc_csu_fini",
    })


# ---------------------------------------------------------------------------
# Platform Summary
# ---------------------------------------------------------------------------

def describe_platform(program):
    """
    Print and return the detected format and architecture for this binary.

    Returns
    -------
    tuple[str, str]
        (fmt, arch) where fmt is 'ELF'/'MACHO'/'PE'/'UNKNOWN'
        and arch is 'x86'/'x86_64'/'ARM64'/etc.
    """
    fmt  = get_binary_format(program)
    arch = get_architecture(program)
    print(
        f"[Platform] Format={fmt}  Arch={arch}  "
        f"ExeFormat='{program.getExecutableFormat()}'  "
        f"Language='{program.getLanguage()}'"
    )
    return fmt, arch
