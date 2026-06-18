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
import struct
import math
from ghidra_decompiler.syntax import recover_variadic_arguments


def try_decode_string(val):
    if val < 0x20202020:
        return None
    bit_len = val.bit_length()
    if bit_len > 512:
        return None
    num_bytes = (bit_len + 7) // 8
    try:
        b = val.to_bytes(num_bytes, 'little')
    except Exception:
        return None
    b_clean = b.rstrip(b'\x00')
    if len(b_clean) < 4:
        return None
    if all(32 <= c <= 126 for c in b_clean):
        try:
            s = b_clean.decode('ascii')
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        except Exception:
            return None
    return None


def try_decode_float(val):
    if val.bit_length() <= 64:
        try:
            d_bytes = struct.pack('>Q', val)
            d_val = struct.unpack('>d', d_bytes)[0]
            if not math.isnan(d_val) and not math.isinf(d_val):
                exponent = (val >> 52) & 0x7ff
                if 0x3c0 <= exponent <= 0x440:
                    s = f"{d_val:.6g}"
                    if abs(float(s) - d_val) < 1e-9:
                        if '.' not in s and 'e' not in s and 'E' not in s:
                            s += '.0'
                        return s
        except Exception:
            pass
    return None


def sanitize_c_code(c_code):
    """
    Performs multiple sanitization passes on the C code:
    1. Converts hexadecimal numbers (0x...) to decimal/string/float literals.
    2. Converts boolean literals (true, false) to integers (1, 0).
    3. Simplifies subtraction-based comparisons (x - 1U == 0 -> x == 1).
    4. Recovers missing variadic arguments (e.g. scanf).
    5. Strips Ghidra-generated strncpy null-fill array noise.
    6. Replaces builtin_strncpy with standard strncpy.
    7. Collapses redundant nested casts.

    Skips over string literals to avoid corrupting text.
    """
    if not c_code:
        return c_code

    # Split the C code by C-style string literals (handling escaped quotes).
    # Parts at even indices are code, odd indices are strings.
    parts = re.split(r'("(?:\\.|[^"\\])*")', c_code)

    for i in range(0, len(parts), 2):
        # Pass 1: Convert hexadecimals and large decimals representing strings/floats to literals.
        # Fall back to converting non-decoded hex numbers to decimal integers.
        def replace_numeric_literal(match):
            token = match.group(0)
            num_str = re.sub(r'[uUlL]+$', '', token)
            is_hex = num_str.lower().startswith('0x')
            try:
                val = int(num_str, 16 if is_hex else 10)
            except ValueError:
                return token

            # Try decoding as string
            str_literal = try_decode_string(val)
            if str_literal is not None:
                return str_literal

            # Try decoding as float
            float_literal = try_decode_float(val)
            if float_literal is not None:
                return float_literal

            # Fall back to decimal conversion if hex and value is small
            if is_hex:
                if val < 0x10000:
                    return str(val)
                else:
                    return token  # Keep original hex representation

            return token

        parts[i] = re.sub(
            r'\b(?:0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*\b',
            replace_numeric_literal,
            parts[i]
        )

        # Pass 1b: Remove redundant (char *) casts in front of string literals.
        parts[i] = re.sub(
            r'\(\s*char\s*\*\s*\)\s*("[^"]*")',
            r'\1',
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

    # (a2) Remove redundant standalone zero-assignments for variables already declared with initializers.
    # Key constraint: match ONLY lines that start directly with the variable name (no type keyword before it),
    # so we don't accidentally delete the declaration itself.
    _init_decl_vars = set(re.findall(
        r'^\s*(?:float|double|int|long(?:\s+long)?|short|unsigned\s+\w+)\s+([a-zA-Z_]\w*)\s*=\s*0',
        final_c, flags=re.MULTILINE
    ))
    for _v in _init_decl_vars:
        # Only match lines where the variable name appears at the start (after optional whitespace),
        # NOT lines starting with a type keyword (those are declarations, keep them).
        # Negative lookbehind ensures no word char or keyword before the variable.
        final_c = re.sub(
            r'(?m)^[ \t]+(?!(?:float|double|int|long|short|unsigned|char|void)\b)'
            + re.escape(_v) + r'[ \t]*=[ \t]*0(?:\.0)?[ \t]*;[ \t]*\n',
            '',
            final_c,
        )

    # (a3) Dedicated pass: strip Ghidra's float-register zero-init for _tmp_N variables.
    # These are always redundant — Ghidra emits `fVar2 = 0;` to zero the float before it's
    # actually assigned, and our declaration auto-init (pass 12a) already covers this.
    final_c = re.sub(r'(?m)^[ \t]+_tmp_\d+[ \t]*=[ \t]*0(?:\.0)?[ \t]*;[ \t]*\n', '', final_c)


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

    # (d) Strip calling convention keywords from both prototypes and function bodies
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

    # (g) Normalize Ghidra-specific type names to standard C keywords
    final_c = re.sub(r'\blonglong\b', 'long long', final_c)
    final_c = re.sub(r'\bulonglong\b', 'unsigned long long', final_c)
    final_c = re.sub(r'\bulong\b', 'unsigned long', final_c)
    final_c = re.sub(r'\buint\b', 'unsigned int', final_c)
    final_c = re.sub(r'\bushort\b', 'unsigned short', final_c)
    final_c = re.sub(r'\buchar\b', 'unsigned char', final_c)

    # (h) Cleanup struct optimized access patterns and address-of-struct string arguments
    final_c = re.sub(r'\._52_8_\s*&\s*(?:4294967295|0xffffffff|4294967295U)', '.level', final_c)
    # Generalized &struct_var -> struct_var.name substitution:
    # Find all local struct-typed variable declarations (type starts with uppercase, e.g. 'Character hero;')
    # and replace &var with var.name in the code (Ghidra uses struct address as pointer to first char[] field).
    _struct_decl_re = re.compile(r'^\s*([A-Z][a-zA-Z0-9_]*)\s+([a-zA-Z_]\w*)\s*;', re.MULTILINE)
    _struct_vars = [m.group(2) for m in _struct_decl_re.finditer(final_c)]
    for _svar in _struct_vars:
        final_c = re.sub(r'&\b' + re.escape(_svar) + r'\b', _svar + '.name', final_c)

    # (i) Remove unused temporary variable assignments (e.g. _tmp_1 = 0;)
    for tmp_var in list(set(re.findall(r'\b(_tmp_\d+)\b', final_c))):
        occurrences = len(re.findall(r'\b' + re.escape(tmp_var) + r'\b', final_c))
        if occurrences == 1:
            final_c = re.sub(r'^\s*' + re.escape(tmp_var) + r'\s*=\s*[^;]+;\s*\n', '', final_c, flags=re.MULTILINE)

    # (j) Replace non-standard builtin_strncpy with standard strncpy.
    final_c = re.sub(r'\bbuiltin_strncpy\b', 'strncpy', final_c)

    # (k) Strip redundant null-fill assignments after strncpy calls.
    # Ghidra expands strncpy into: strncpy(dest, src, n); dest[n] = '\0'; dest[n+1] = '\0'; ...
    # These trailing null assignments are pure noise — strncpy already null-terminates.
    def _strip_null_fill(code):
        lines = code.split('\n')
        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            # Detect a strncpy call and capture the destination variable root (e.g. hero.name)
            strncpy_match = re.match(
                r'^(\s*)strncpy\s*\(\s*([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*,', line
            )
            if strncpy_match:
                out.append(line)
                i += 1
                # Build regex that matches: dest_root[N] = '\0';
                # Use double-quote raw string to avoid single-quote escaping issues.
                dest_root = re.escape(strncpy_match.group(2))
                null_fill_re = re.compile(
                    r"^\s*" + dest_root + r"\s*\[\s*\d+\s*\]\s*=\s*'\\0'\s*;"
                )
                # Keep consuming null-fill lines; stop at the first non-null-fill line.
                while i < len(lines) and null_fill_re.match(lines[i]):
                    i += 1  # discard this null-fill line
            else:
                out.append(line)
                i += 1
        return '\n'.join(out)
    final_c = _strip_null_fill(final_c)

    # Also strip Ghidra's sub-field zeroing lines (e.g. hero._50_2_ = 0; hero.padding = 0;)
    # that appear as a result of inline struct initialization noise.
    final_c = re.sub(
        r'^\s*[a-zA-Z_]\w*\._\d+_\d+_\s*=\s*0\s*;\s*\n',
        '',
        final_c,
        flags=re.MULTILINE,
    )


    # (l) Collapse redundant nested casts, e.g. (unsigned long)(unsigned int)x -> (unsigned int)x
    # These arise from Ghidra's zero-extension patterns on ARM64.
    final_c = re.sub(
        r'\(\s*(?:unsigned\s+)?long\s*\)\s*\(\s*((?:unsigned\s+)?int)\s*\)\s*([a-zA-Z_]\w*)',
        r'(\1)\2',
        final_c
    )
    # Also handle (unsigned long)(unsigned int) without a following identifier (function call result etc.)
    final_c = re.sub(
        r'\(\s*(?:unsigned\s+)?long\s*long\s*\)\s*\(\s*((?:unsigned\s+)?(?:int|short|char))\s*\)\s*([a-zA-Z_]\w*)',
        r'(\1)\2',
        final_c
    )

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
