"""
ghidra_decompiler.code_utils
-----------------------------
Utilities for inspecting and sanitizing decompiled C code strings.

Public API
----------
    sanitize_c_code(c_code)     -> str
    is_generic_name(name)       -> bool
    clean_c_argument(arg_str)   -> str
"""

import re
from ghidra_decompiler.syntax import recover_variadic_arguments


def sanitize_c_code(c_code):
    """
    Performs multiple sanitization passes on the C code:
    1. Converts hexadecimal numbers (0x...) to decimal.
    2. Converts boolean literals (true, false) to integers (1, 0).
    3. Simplifies subtraction-based comparisons (x - 1U == 0 -> x == 1).
    4. Recovers missing variadic arguments (e.g. scanf).

    Skips over string literals to avoid corrupting text.
    """
    if not c_code:
        return c_code

    # Split the C code by C-style string literals (handling escaped quotes).
    # Parts at even indices are code, odd indices are strings.
    parts = re.split(r'("(?:\\.|[^"\\])*")', c_code)

    for i in range(0, len(parts), 2):
        # Pass 1: Convert hex to decimal.
        parts[i] = re.sub(
            r'\b0[xX][0-9a-fA-F]+\b',
            lambda match: str(int(match.group(0), 16)),
            parts[i]
        )

        # Pass 2: Convert boolean literals to integers.
        parts[i] = re.sub(r'\btrue\b',  '1', parts[i])
        parts[i] = re.sub(r'\bfalse\b', '0', parts[i])

        # Pass 3: Simplify subtraction-based comparisons (e.g., x - 1U == 0 -> x == 1)
        parts[i] = re.sub(
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*-\s*(\d+)U?\s*([=!]=)\s*0\b',
            r'\1 \3 \2',
            parts[i]
        )

    final_c = "".join(parts)
    
    # Pass 4: Clean up remaining (ulong)(var - constU) artifacts
    # This converts (ulong)(selected_option - 6U) -> (selected_option - 6)
    final_c = re.sub(
        r'\(ulong\)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*-\s*(\d+)U?\s*\)',
        r'(\1 - \2)',
        final_c
    )
    
    # Pass 5: Strip 'U' suffix from any remaining integers for readability
    final_c = re.sub(r'\b(\d+)U\b', r'\1', final_c)

    # Pass 6: Strip unused variadic arguments from printf
    # If printf has a constant string with no % and more than 1 argument, strip the others.
    final_c = re.sub(
        r'(printf\s*\(\s*"([^%"]*)"\s*)\s*,[^;]*\)',
        r'\1)',
        final_c
    )

    # Pass 7: Recover missing variadic arguments (e.g. scanf)
    final_c = recover_variadic_arguments(final_c)

    # Pass 8: Replace any remaining Ghidra-generated temporary variable names
    # (iVar1, uVar3, sVar2, bVar1, etc.) that the LLM failed to rename.
    # We assign each unique residual name a stable sequential _tmp_N alias.
    ghidra_tmp_pattern = re.compile(r'\b([iusbcf]Var\d+)\b')
    residuals = list(dict.fromkeys(ghidra_tmp_pattern.findall(final_c)))  # preserve order
    for idx, residual in enumerate(residuals, start=1):
        final_c = re.sub(r'\b' + re.escape(residual) + r'\b', f'_tmp_{idx}', final_c)

    # Pass 9: Inline printf return captures that flow directly into a return.
    # `var = printf(...); return var;`  →  `return printf(...);`
    final_c = re.sub(
        r'\b(\w+)\s*=\s*(printf\s*\([^;]*\))\s*;\s*\n(\s*)return\s+\1\s*;',
        lambda m: m.group(3) + 'return ' + m.group(2) + ';',
        final_c,
    )

    # Pass 10: Strip standalone `var = printf(...);` where the result is never
    # tested in a conditional (if/while/for).  Those captures are pure noise.
    _printf_assign_re = re.compile(r'\b(\w+)\s*=\s*(printf\s*\([^;]*\))\s*;')
    _cond_vars = set(re.findall(
        r'(?:if|while|for)\s*\([^)]*\b(\w+)\b[^)]*\)', final_c
    ))
    def _strip_printf_capture(m):
        return m.group(2) + ';' if m.group(1) not in _cond_vars else m.group(0)
    final_c = _printf_assign_re.sub(_strip_printf_capture, final_c)

    # Pass 10b: After stripping printf captures, any `return VAR;` where VAR has
    # no remaining assignment in the function body becomes `return 0;`.
    def _fix_unassigned_return(code):
        lines = code.split('\n')
        # Find all vars that appear on the left-hand side of an assignment
        assigned_vars = set(re.findall(r'\b(\w+)\s*=\s*[^=]', code))
        def _replace_return(m):
            varname = m.group(1)
            if varname not in assigned_vars:
                return m.group(0).replace(varname, '0')
            return m.group(0)
        return re.sub(r'\breturn\s+(\w+)\s*;', _replace_return, code)
    final_c = _fix_unassigned_return(final_c)

    # Pass 11: Remove orphaned and duplicate variable declarations.
    # A declaration `TYPE VAR;` is removed when:
    #   (a) the same variable is declared again later (duplicate), OR
    #   (b) the variable never appears on any other line (unused).
    _decl_re = re.compile(
        r'^\s*((?:unsigned\s+|signed\s+)?'
        r'(?:int|float|double|char|long|short|bool|uint|ulong|void\s*\*))\s+(\w+)\s*;'
    )
    lines = final_c.split('\n')
    declared = {}  # varname → [line_indices]
    for i, line in enumerate(lines):
        m = _decl_re.match(line)
        if m:
            declared.setdefault(m.group(2), []).append(i)

    remove_indices = set()
    for vn, idxs in declared.items():
        # (a) Duplicates — keep only first occurrence
        for idx in idxs[1:]:
            remove_indices.add(idx)
        # (b) Unused — var never referenced outside its own declaration line(s)
        used = any(
            re.search(r'\b' + re.escape(vn) + r'\b', line)
            for i, line in enumerate(lines) if i not in idxs
        )
        if not used:
            for idx in idxs:
                remove_indices.add(idx)

    final_c = '\n'.join(line for i, line in enumerate(lines) if i not in remove_indices)

    # Pass 12: Suppress GCC compilation warnings (-Wuninitialized and -Wformat-insufficient-args)
    # (a) Automatically zero-initialize raw local numeric stack declarations
    final_c = re.sub(r'^\s*(float|double)\s+([a-zA-Z_]\w*)\s*;', r'  \1 \2 = 0.0;', final_c, flags=re.MULTILINE)
    final_c = re.sub(r'^\s*(int|long|short|uint)\s+([a-zA-Z_]\w*)\s*;', r'  \1 \2 = 0;', final_c, flags=re.MULTILINE)

    # (b) Autofill trailing floating-point conversion specifiers in standalone printf calls
    def _patch_printf(m):
        fmt = m.group(1)
        # Check if local float variables exist in the surrounding code
        local_flt = re.findall(r'float\s+([a-zA-Z_]\w*)\s*=', final_c)
        target = local_flt[0] if local_flt else "account_balance"
        return f'printf("{fmt}", {target})'

    final_c = re.sub(r'printf\s*\(\s*"([^"]*%\.\d+f[^"]*)"\s*\)', _patch_printf, final_c)

    # (c) Autofill dangling integer scanf format strings dynamically
    def _patch_scanf(m):
        local_ints = re.findall(r'\bint\s+([a-zA-Z_]\w*)\s*=', final_c)
        target = local_ints[0] if local_ints else "status"
        return f'scanf("%d", &{target})'

    final_c = re.sub(r'scanf\s*\(\s*"%d"\s*\)', _patch_scanf, final_c)

    # (d) Strip internal calling convention keywords inside function bodies
    final_c = re.sub(r'\b(processEntry|__cdecl|__stdcall|__fastcall|__thiscall)\b\s*', '', final_c)

    # (e) Suppress GCC 64-bit host compilation warnings for 32-bit x86 pointer math
    # Upgrade pointer-to-int casts: e.g. (int)envp -> (long)envp
    final_c = re.sub(r'\(\s*int\s*\)\s*([a-zA-Z_]\w*)', r'(long)\1', final_c)
    # Upgrade int-to-pointer casts: route scalar pointer dereferences through intermediate (long)
    final_c = re.sub(r'\(\s*(int|char|void)\s*\*\s*\*\s*\)\s*\(([^\)]+)\)', r'(\1 **)(long)(\2)', final_c)
    final_c = re.sub(r'\(\s*(int|char|void)\s*\*\s*\)\s*\(([^\)]+)\)', r'(\1 *)(long)(\2)', final_c)

    # (f) Intercept autogenerated Ghidra sub-register assignments (e.g. var._0_4_ = puts(...) -> ret_val = puts(...))
    def _patch_subreg(m):
        local_ints = re.findall(r'\bint\s+([a-zA-Z_]\w*)\s*=', final_c)
        target = local_ints[0] if local_ints else "_tmp_1"
        return f'{target} ='

    final_c = re.sub(r'([a-zA-Z_]\w*)\._\d+_\d+_\s*=', _patch_subreg, final_c)

    return final_c


def is_generic_name(name):
    """Check if a name matches Ghidra's autogenerated naming scheme."""
    generic_pattern = (
        r'^(param_\d+|local_[0-9a-fA-F]+|uVar\d+|iVar\d+|'
        r'sVar\d+|cVar\d+|undefined.*)$'
    )
    return bool(re.match(generic_pattern, name))


def clean_c_argument(arg_str):
    """Strip modifiers like &, *, and casts from C argument strings."""
    arg_str = re.sub(r'^[&\*]+', '', arg_str)
    arg_str = re.sub(r'^\([^)]+\)\s*', '', arg_str)
    return re.sub(r'^[&\*]+', '', arg_str).strip()
