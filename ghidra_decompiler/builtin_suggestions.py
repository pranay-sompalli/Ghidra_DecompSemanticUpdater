"""
ghidra_decompiler.builtin_suggestions
------------------------------------
Static analysis helpers to extract variable name and type suggestions from standard C
built-in function calls (like printf/scanf) and retrieve variable usage lines.
"""

import re
from ghidra_decompiler.code_utils import is_generic_name, clean_c_argument

# Mapping of common C standard library functions to their header.
# Used to tell the LLM exactly which builtins are called so it can
# suggest the correct #include directives.
STDLIB_FUNCTIONS = {
    # <stdio.h>
    "printf":    "<stdio.h>",
    "fprintf":   "<stdio.h>",
    "sprintf":   "<stdio.h>",
    "snprintf":  "<stdio.h>",
    "scanf":     "<stdio.h>",
    "fscanf":    "<stdio.h>",
    "sscanf":    "<stdio.h>",
    "fopen":     "<stdio.h>",
    "fclose":    "<stdio.h>",
    "fread":     "<stdio.h>",
    "fwrite":    "<stdio.h>",
    "fgets":     "<stdio.h>",
    "fputs":     "<stdio.h>",
    "feof":      "<stdio.h>",
    "fseek":     "<stdio.h>",
    "ftell":     "<stdio.h>",
    "rewind":    "<stdio.h>",
    "puts":      "<stdio.h>",
    "getchar":   "<stdio.h>",
    "putchar":   "<stdio.h>",
    "perror":    "<stdio.h>",
    "remove":    "<stdio.h>",
    "rename":    "<stdio.h>",
    "tmpfile":   "<stdio.h>",
    "wprintf":   "<stdio.h>",
    "wscanf":    "<stdio.h>",
    # <stdlib.h>
    "malloc":    "<stdlib.h>",
    "calloc":    "<stdlib.h>",
    "realloc":   "<stdlib.h>",
    "free":      "<stdlib.h>",
    "exit":      "<stdlib.h>",
    "abort":     "<stdlib.h>",
    "atoi":      "<stdlib.h>",
    "atol":      "<stdlib.h>",
    "atof":      "<stdlib.h>",
    "strtol":    "<stdlib.h>",
    "strtod":    "<stdlib.h>",
    "rand":      "<stdlib.h>",
    "srand":     "<stdlib.h>",
    "qsort":     "<stdlib.h>",
    "bsearch":   "<stdlib.h>",
    "getenv":    "<stdlib.h>",
    "system":    "<stdlib.h>",
    # <string.h>
    "strlen":    "<string.h>",
    "strcpy":    "<string.h>",
    "strncpy":   "<string.h>",
    "strcat":    "<string.h>",
    "strncat":   "<string.h>",
    "strcmp":    "<string.h>",
    "strncmp":   "<string.h>",
    "strchr":    "<string.h>",
    "strrchr":   "<string.h>",
    "strstr":    "<string.h>",
    "strtok":    "<string.h>",
    "memcpy":    "<string.h>",
    "memmove":   "<string.h>",
    "memset":    "<string.h>",
    "memcmp":    "<string.h>",
    "strdup":    "<string.h>",
    # <math.h>
    "sqrt":      "<math.h>",
    "pow":       "<math.h>",
    "abs":       "<math.h>",
    "fabs":      "<math.h>",
    "floor":     "<math.h>",
    "ceil":      "<math.h>",
    "round":     "<math.h>",
    "log":       "<math.h>",
    "log2":      "<math.h>",
    "log10":     "<math.h>",
    "exp":       "<math.h>",
    "sin":       "<math.h>",
    "cos":       "<math.h>",
    "tan":       "<math.h>",
    "atan2":     "<math.h>",
    # <ctype.h>
    "isdigit":   "<ctype.h>",
    "isalpha":   "<ctype.h>",
    "isalnum":   "<ctype.h>",
    "isspace":   "<ctype.h>",
    "isupper":   "<ctype.h>",
    "islower":   "<ctype.h>",
    "toupper":   "<ctype.h>",
    "tolower":   "<ctype.h>",
    # <time.h>
    "time":      "<time.h>",
    "clock":     "<time.h>",
    "difftime":  "<time.h>",
    "mktime":    "<time.h>",
    "strftime":  "<time.h>",
    "localtime": "<time.h>",
    "gmtime":    "<time.h>",
    # <unistd.h>  (POSIX)
    "read":      "<unistd.h>",
    "write":     "<unistd.h>",
    "close":     "<unistd.h>",
    "open":      "<unistd.h>",
    "sleep":     "<unistd.h>",
    "getpid":    "<unistd.h>",
    "getuid":    "<unistd.h>",
    "fork":      "<unistd.h>",
    "execve":    "<unistd.h>",
    # <pthread.h>  (POSIX threads)
    "pthread_create":  "<pthread.h>",
    "pthread_join":    "<pthread.h>",
    "pthread_mutex_lock":   "<pthread.h>",
    "pthread_mutex_unlock": "<pthread.h>",
    # <errno.h>
    "errno":     "<errno.h>",
    "strerror":  "<string.h>",
    # <signal.h>
    "signal":    "<signal.h>",
    "raise":     "<signal.h>",
    # <setjmp.h>
    "setjmp":    "<setjmp.h>",
    "longjmp":   "<setjmp.h>",
}


def get_detected_builtins(c_code):
    """
    Scan decompiled C code for calls to known standard library functions.

    Returns a list of (function_name, header) tuples for every unique stdlib
    function that is called in c_code, sorted by function name.
    """
    if not c_code:
        return []
    pattern = re.compile(
        r'\b(' + '|'.join(re.escape(f) for f in STDLIB_FUNCTIONS) + r')\s*\('
    )
    found = set()
    for m in pattern.finditer(c_code):
        func = m.group(1)
        found.add((func, STDLIB_FUNCTIONS[func]))
    return sorted(found, key=lambda x: x[0])


# C keywords and control-flow tokens that look like calls but are not functions.
_C_KEYWORDS = frozenset({
    "if", "else", "while", "for", "do", "switch", "case", "return",
    "sizeof", "typeof", "alignof", "offsetof", "defined",
    "break", "continue", "goto", "typedef", "struct", "union", "enum",
    "__attribute__", "__builtin_expect", "__typeof__",
})


def get_unknown_external_calls(c_code, known_func_names=None):
    """
    Detect calls to functions that are NOT in STDLIB_FUNCTIONS and NOT in
    the set of known user-defined function names (e.g. callees from the binary).

    These are likely external library functions we have no header mapping for.
    Returns a sorted list of unique unknown function names.

    Args:
        c_code: Decompiled C source for one function.
        known_func_names: An iterable of function names that belong to the
            binary itself (e.g. callee names from the pipeline).  These are
            excluded from the result.
    """
    if not c_code:
        return []

    known = set(known_func_names or [])
    clean = strip_comments(c_code)

    # Match every token followed by '(' — these are potential call sites.
    call_pattern = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
    unknown = set()
    for m in call_pattern.finditer(clean):
        name = m.group(1)
        if name in _C_KEYWORDS:
            continue
        if name in STDLIB_FUNCTIONS:
            continue
        if name in known:
            continue
        # Skip names that are clearly generic Ghidra temporaries (FUN_xxx, local_xx …)
        if re.match(r'^(FUN_|SUB_|DAT_|LAB_|PTR_|thunk_|local_|param_)', name, re.IGNORECASE):
            continue
        unknown.add(name)

    return sorted(unknown)

FORMAT_FUNCS = {
    "printf": 0,
    "scanf": 0,
    "wprintf": 0,
    "wscanf": 0,
    "fprintf": 1,
    "fscanf": 1,
    "sprintf": 1,
    "sscanf": 1,
    "snprintf": 2,
}

GENERIC_WORDS = {
    "is", "the", "a", "an", "of", "to", "for", "in", "on", "at",
    "by", "with", "and", "or", "please", "enter", "input", "select",
    "your", "here", "to", "be"
}


def strip_comments(c_code):
    """Strip block and line comments from C code, ignoring string literals."""
    if not c_code:
        return ""
    # Split the C code by C-style string literals to avoid comment matching inside them
    parts = re.split(r'("(?:\\.|[^"\\])*")', c_code)
    for i in range(0, len(parts), 2):
        # Strip block comments /* ... */
        parts[i] = re.sub(r'/\*.*?\*/', '', parts[i], flags=re.DOTALL)
        # Strip line comments // ...
        parts[i] = re.sub(r'//.*', '', parts[i])
    return "".join(parts)


def split_arguments(arg_str):
    """Split function call arguments by comma, respecting nested parentheses and strings."""
    if not arg_str:
        return []
    args = []
    current = []
    depth = 0
    in_string = False
    escaped = False
    
    for char in arg_str:
        if in_string:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                in_string = False
            current.append(char)
        else:
            if char == '"':
                in_string = True
                current.append(char)
            elif char == '(':
                depth += 1
                current.append(char)
            elif char == ')':
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                args.append("".join(current).strip())
                current = []
            else:
                current.append(char)
    if current:
        args.append("".join(current).strip())
    return args


def specifier_to_type(spec):
    """Map a format specifier to standard C type."""
    if '%' not in spec:
        return None
    s = spec.replace('%', '')
    
    if 'll' in s or 'I64' in s:
        if 'd' in s or 'i' in s:
            return 'long long'
        if 'u' in s or 'x' in s or 'o' in s:
            return 'unsigned long long'
    elif 'l' in s:
        if 'd' in s or 'i' in s:
            return 'long'
        if 'u' in s or 'x' in s or 'o' in s:
            return 'unsigned long'
        if 'f' in s or 'F' in s or 'g' in s:
            return 'double'
    elif 'h' in s:
        if 'd' in s or 'i' in s:
            return 'short'
        if 'u' in s or 'x' in s or 'o' in s:
            return 'unsigned short'
            
    if 'd' in s or 'i' in s:
        return 'int'
    if 'u' in s or 'x' in s or 'o' in s:
        return 'unsigned int'
    if 'f' in s or 'g' in s:
        return 'float'
    if 's' in s:
        return 'char *'
    if 'c' in s:
        return 'char'
    if 'p' in s:
        return 'void *'
    return None


def get_label_from_prefix(prefix):
    """Extract a descriptive lower_snake_case label/name from format prefix or prompt text."""
    prefix = re.sub(r'[\s:=,\-\n\r\t]+$', '', prefix)
    if not prefix:
        return None
    # Find all words containing only letters and underscores
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', prefix)
    if not words:
        return None
        
    # Walk backward to find the first non-generic word
    idx = len(words) - 1
    while idx >= 0 and words[idx].lower() in GENERIC_WORDS:
        idx -= 1
        
    if idx >= 0:
        last_word = words[idx].lower()
        # If we have a preceding word that fits well (e.g. "user", "file", "total", "input"), combine them
        if idx > 0 and words[idx-1].lower() in ("user", "file", "total", "input", "new", "old", "curr", "prev", "min", "max"):
            return f"{words[idx-1].lower()}_{last_word}"
        return last_word
    else:
        # Fall back to the absolute last word if all were generic
        return words[-1].lower()


def is_generic_or_tmp_name(name):
    """Check if a name is generic or a temporary identifier like _tmp_1."""
    if not name:
        return False
    return is_generic_name(name) or bool(re.match(r'^_?tmp_\d+$', name))


def find_format_calls(c_code):
    """Find all calls to supported format functions in the C code, respecting nesting."""
    c_code = strip_comments(c_code)
    calls = []
    
    # Match function name followed by opening parenthesis
    pattern = re.compile(
        r'\b(printf|scanf|wprintf|wscanf|fprintf|fscanf|sprintf|sscanf|snprintf)\s*\('
    )
    
    for match in pattern.finditer(c_code):
        func_name = match.group(1)
        start_idx = match.end()
        
        depth = 1
        in_string = False
        escaped = False
        end_idx = start_idx
        
        while end_idx < len(c_code) and depth > 0:
            char = c_code[end_idx]
            if in_string:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
            end_idx += 1
            
        if depth == 0:
            args_str = c_code[start_idx:end_idx-1]
            calls.append({
                "name": func_name,
                "args_str": args_str,
                "start_pos": match.start()
            })
            
    return calls


def analyze_call(call):
    """Analyze arguments and extract details from format calls."""
    name = call["name"]
    args = split_arguments(call["args_str"])
    fmt_idx = FORMAT_FUNCS.get(name, 0)
    
    if len(args) <= fmt_idx:
        return None
        
    fmt_arg = args[fmt_idx]
    # Check if format argument is a string literal (ignoring casts if present)
    clean_fmt = re.sub(r'^\([^)]+\)\s*', '', fmt_arg).strip()
    if not (clean_fmt.startswith('"') and clean_fmt.endswith('"')):
        return None
        
    fmt_str = clean_fmt[1:-1]
    
    # Find format specifiers, ignoring %%
    specifiers = re.findall(
        r'%(?:%|[-+0 #]*\d*(?:\.\d+)?[lhL]*[diuoxXfFeEgGaAcspn])',
        fmt_str
    )
    specifiers = [s for s in specifiers if s != '%%']
    
    var_args = args[fmt_idx + 1:]
    
    return {
        "name": name,
        "fmt_str": fmt_str,
        "specifiers": specifiers,
        "var_args": var_args,
        "start_pos": call["start_pos"]
    }


def extract_builtin_suggestions(c_code):
    """
    Statically analyze standard calls to extract type and name suggestions
    for generic variables.
    """
    calls = find_format_calls(c_code)
    analyzed_calls = []
    for call in calls:
        analyzed = analyze_call(call)
        if analyzed:
            analyzed_calls.append(analyzed)
            
    suggestions = {}
    
    for i, call in enumerate(analyzed_calls):
        name = call["name"]
        specifiers = call["specifiers"]
        var_args = call["var_args"]
        
        # Split format string by specifiers to extract surrounding text
        parts = re.split(
            r'(%(?:%|[-+0 #]*\d*(?:\.\d+)?[lhL]*[diuoxXfFeEgGaAcspn]))',
            call["fmt_str"]
        )
        
        spec_parts = []
        part_idx = 0
        for part in parts:
            if part.startswith('%') and part != '%%':
                spec_parts.append((part, part_idx))
            part_idx += 1
            
        # 1. Specifier-to-argument mapping
        for j, (spec, part_idx) in enumerate(spec_parts):
            if j < len(var_args):
                arg = var_args[j]
                clean_arg = clean_c_argument(arg)
                if clean_arg and is_generic_or_tmp_name(clean_arg):
                    t = specifier_to_type(spec)
                    prefix = parts[part_idx - 1]
                    label = get_label_from_prefix(prefix)
                    
                    if clean_arg not in suggestions:
                        suggestions[clean_arg] = {"new_names": set(), "new_types": set()}
                    if t:
                        suggestions[clean_arg]["new_types"].add(t)
                    if label:
                        suggestions[clean_arg]["new_names"].add(label)
                        
        # 2. Prompt-response mapping (e.g. printf("Enter choice: ") followed by scanf)
        if "scanf" in name and i > 0:
            prev_call = analyzed_calls[i-1]
            if "printf" in prev_call["name"]:
                if not prev_call["specifiers"]:
                    prompt_text = prev_call["fmt_str"]
                    label = get_label_from_prefix(prompt_text)
                    if label and var_args:
                        first_arg = var_args[0]
                        clean_first_arg = clean_c_argument(first_arg)
                        if clean_first_arg and is_generic_or_tmp_name(clean_first_arg):
                            if clean_first_arg not in suggestions:
                                suggestions[clean_first_arg] = {"new_names": set(), "new_types": set()}
                            suggestions[clean_first_arg]["new_names"].add(label)
                            
    final_suggestions = {}
    for var, data in suggestions.items():
        name_list = sorted(list(data["new_names"]), key=len, reverse=True) # Prefer longer labels
        type_list = list(data["new_types"])
        
        suggested_name = name_list[0] if name_list else None
        suggested_type = type_list[0] if type_list else None
        
        if suggested_name or suggested_type:
            final_suggestions[var] = {}
            if suggested_name:
                final_suggestions[var]["new_name"] = suggested_name
            if suggested_type:
                final_suggestions[var]["new_type_str"] = suggested_type
                
    return final_suggestions


def extract_variable_usages(c_code, var_name):
    """
    Find all lines in c_code where var_name is used, excluding pure declaration lines.
    """
    if not c_code or not var_name:
        return []
    
    # Strip comments first to prevent matches in comments
    clean_code = strip_comments(c_code)
    lines = clean_code.splitlines()
    usages = []
    
    # Whole-word match for the variable name
    pattern = re.compile(r'\b' + re.escape(var_name) + r'\b')
    
    # Matches a type declaration, e.g., "int local_1c;" or "char * local_1c = ..."
    decl_pattern = re.compile(
        r'^\s*(?:unsigned\s+|signed\s+)?(?:int|float|double|char|long|short|bool|uint|ulong|void\s*\*|[A-Z]\w*)\s*(?:\*\s*)?'
        + re.escape(var_name) + r'\b'
    )
    
    for line in lines:
        if pattern.search(line):
            if decl_pattern.search(line):
                continue
            usages.append(line.strip())
            
    return usages
