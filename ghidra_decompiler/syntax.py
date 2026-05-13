
import re

def recover_variadic_arguments(c_code):
    """
    Heuristically recover missing arguments for common libc calls (scanf, printf).
    Currently focuses on scanf calls missing their target variable pointers.
    """
    if not c_code:
        return c_code

    lines = c_code.splitlines()
    new_lines = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # 1. Detect scanf with missing arguments
        # Matches: var = scanf("...");  or  scanf("...");
        scanf_match = re.search(r'((\b([a-zA-Z_][a-zA-Z0-9_]*)\b\s*=\s*)?\bscanf\s*\(\s*"([^"]*)"\s*\))', line)
        if scanf_match:
            full_call  = scanf_match.group(1)
            return_var = scanf_match.group(3)
            fmt_str    = scanf_match.group(4)
            
            # Count placeholders
            placeholders = len(re.findall(r'%[dfsxu]', fmt_str))
            
            if placeholders > 0 and "," not in line[scanf_match.start():scanf_match.end()]:
                candidate = None
                # Look ahead for potential candidates (next 10 lines)
                for j in range(i + 1, min(i + 11, len(lines))):
                    # Look for variable usage in a comparison or logic that ISN'T a function call
                    # We search for: VAR ==, VAR !=, VAR <, VAR >, VAR -
                    usage_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b\s*([=!<>]=|[<>+\-])', lines[j])
                    if usage_match:
                        var_name = usage_match.group(1)
                        # Skip keywords, return values, and things followed by (
                        if (var_name not in ("if", "while", "return", "for") and 
                            var_name != return_var and 
                            not re.search(r'\b' + re.escape(var_name) + r'\b\s*\(', lines[j])):
                            candidate = var_name
                            break
                
                if candidate:
                    prefix = scanf_match.group(2) or ""
                    new_call = '{}scanf("{}", &{})'.format(prefix, fmt_str, candidate)
                    line = line.replace(full_call, new_call)
                    print("[Syntax] Recovered scanf argument: '{}' -> '{}'".format(full_call, new_call))
        
        new_lines.append(line)
        i += 1
        
    return "\n".join(new_lines)
