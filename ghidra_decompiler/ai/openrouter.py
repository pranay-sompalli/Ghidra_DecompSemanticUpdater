"""
ghidra_decompiler.ai.openrouter
-------------------------------
Uses the OpenRouter API to suggest semantically meaningful variable names,
parameter names, types, and required #include / #define directives for a
decompiled C function.

Supported models
----------------
    openrouter/free (default — auto routes to a fast free model)
    qwen/qwen3-coder:free

Environment variable required
------------------------------
    OPEN_ROUTER_API_KEY  — your OpenRouter API key

Public API
----------
    get_openrouter_suggestions(decompiled_c, model, callee_snippets, ...) -> dict

    Returns:
        {
            "function_name": "suggested_name",
            "variables": [
                {"name": "local_8",  "new_name": "counter",  "new_type_str": "int"},
                ...
            ],
            "parameters": [
                {"name": "param_1",  "new_name": "filename", "new_type_str": "char *"},
                ...
            ],
            "includes": ["<stdio.h>", "<stdlib.h>"],
            "defines":  ["#define MAX_SIZE 256"],
        }

    On any failure the function returns a dict with empty lists for all keys so
    the caller can always iterate safely.
"""

import os
import json
import re
import time
import hashlib

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert reverse engineer and C programmer. \
You will be given raw decompiled C pseudocode produced by Ghidra. \
Your job is to infer the most semantically accurate names and C types for \
every local variable and every function parameter visible in the code.

Rules:
- CRITICAL: Only suggest names/types for identifiers that LITERALLY APPEAR as variable or parameter names in the provided code. Do NOT invent new variables. Do NOT add entries for variables that are not declared in the code.
- CRITICAL: Do NOT use C reserved keywords or primitive type names as new_name values. Never use 'long', 'float', 'int', 'char', 'double', 'void', 'unsigned', 'struct', 'short', 'bool' etc. as variable names.
- CRITICAL: Do NOT use struct/union/enum type names as variable names. Type names (like 'Character', 'Player') identify types, not variables.
- CRITICAL: Global variables in the 'globals' list must be actual symbol names visible in the decompiled code (like PTR___stack_chk_guard_00102000, DAT_00104020). Do NOT list raw hex constants (0x10, 0x2a) or struct field access patterns as globals.
- Identify Global Variables (variables not declared inside the function body or its parameters, often prefixed with `PTR_` or `DAT_`) and suggest their types based on how the function interacts with them (e.g., if passed to `%f` in scanf, it's a `float`).
- Analyze what the function does and suggest a descriptive function name (e.g., 'verify_password' instead of 'check').
- Use standard C type strings: "int", "unsigned int", "long", "char",
  "char *", "char **", "void *", "void", "float", "double",
  "unsigned char", "short", "unsigned short".
- Analyze the provided C code for custom types that might be used in the code and add them to the custom_types list. For each custom type, provide the name, type, and members (for struct and union) or values (for enum). 
- For "struct" and "union" custom types, ensure memory offsets are precise. A "union" must have all member offsets set to 0. A "struct" must have sequential offsets accounting for standard data-type sizes and alignment padding.
- If loose stack primitive variables (e.g., buffer arrays, ints, floats) are clustered together and behave like fields of a single struct, group them into a custom type, and update those original variable identifiers to use that new custom type name.
- Prefer descriptive, lower_snake_case names (e.g. "buffer_size", "file_ptr").
- If a variable or parameter already has a reasonable name, you may keep it
  (omit from the list or repeat the same name).
- Suggest any necessary standard C headers (as #include directives, e.g. "<stdio.h>") and any necessary #define macros or constants that the code might rely on to successfully compile.
- Provide a "context" field which is a concise (1-2 sentence) technical summary of what the function does and its primary goal.
- If you see generic register variables like 'iVar1' or 'uVar2' being reused for multiple unrelated function returns, ALWAYS rename them to a generic name like 'temp', 'ret_val', or 'status' instead of leaving them as is.
- Return ONLY a single valid JSON object — no markdown, no prose.

JSON schema (strict):
{
  "function_name": "<new_function_name>",
  "context": "<brief_summary_of_function_purpose>",
  "variables": [
    {"name": "<current_name>", "new_name": "<suggested_name>", "new_type_str": "<c_type>"}
  ],
  "parameters": [
    {"name": "<current_name>", "new_name": "<suggested_name>", "new_type_str": "<c_type>"}
  ],
  "globals": [
    {"name": "<current_name>", "new_name": "<suggested_name>", "new_type_str": "<c_type>"}
  ],
  "includes": [
    "<stdio.h>",
    "<stdlib.h>"
  ],
  "defines": [
    "#define MAX_BUFFER 1024"
  ],
  "custom_types": [
    {
      "name": "<struct_name>",
      "type": "struct", 
      "members": [
        {"offset": 0, "name": "<field_name>", "type": "int"},
        {"offset": 4, "name": "<field_name>", "type": "char*"}
      ]
    },
    {
      "name": "<union_name>",
      "type": "union",
      "members": [
        {"offset": 0, "name": "<field_name>", "type": "int"},
        {"offset": 0, "name": "<field_name>", "type": "char*"} 
      ]
    },
    {
      "name": "<enum_name>",
      "type": "enum",
      "values": [
        {"name": "<value_name>", "value": 0}
      ]
    },
    {
      "name": "<typedef_name>",
      "type": "typedef",
      "underlying_type": "<underlying_type>"
    }
  ]
}
"""

_USER_PROMPT_TEMPLATE = """\
{context_header}\
{callers_header}\
{callees_header}\
{strings_header}\
Analyze the following decompiled C function and suggest better variable and \
parameter names/types. Return ONLY the JSON object described in the system prompt.


Keep parameter and variable names consistent with any reference context provided above.

```c
{decompiled_c}
```
"""

_USAGE_SYSTEM_PROMPT = """\
You are an expert reverse engineer and C programmer.
You will be given a list of local variables and function parameters, their types, and the exact lines of C code where they are used.
You will also receive two sections:
- "Detected Standard Library Calls": functions with already-known headers — add them to "includes".
- "Unknown External Calls": function names with no known header — infer the correct #include for each and add them to "includes".

Your job is to:
1. Suggest a descriptive, semantically accurate new name for each variable/parameter.
2. Suggest a descriptive function name (e.g. 'verify_password', 'calculate_sum') based on how the variables are used.
3. Suggest a brief 1-2 sentence context summarizing the function's purpose.
4. Populate "includes" with all required #include directives (e.g. "<stdio.h>").

Rules:
- Prefer descriptive, lower_snake_case names (e.g. "buffer_size", "file_ptr").
- Do NOT use C reserved keywords or primitive type names as names (never use 'long', 'float', 'int', 'char', etc.).
- Do NOT suggest names that are already types.
- Return ONLY a single valid JSON object matching the schema below — no markdown, no prose.

JSON schema (strict):
{
  "function_name": "<suggested_function_name>",
  "context": "<brief_summary_of_function_purpose>",
  "variables": [
    {"name": "<current_name>", "new_name": "<suggested_name>", "new_type_str": "<c_type>"}
  ],
  "parameters": [
    {"name": "<current_name>", "new_name": "<suggested_name>", "new_type_str": "<c_type>"}
  ],
  "globals": [],
  "includes": ["<stdio.h>", "<stdlib.h>"],
  "defines": [],
  "custom_types": []
}
"""

_USAGE_USER_PROMPT_TEMPLATE = """\
Analyze the following variables, their types, and usages from a decompiled C function, and suggest better names.

Variables:
{variables_details}

{unknowns_header}\
Return ONLY the JSON object described in the system prompt.
"""

# Used when all variables are already well-named (Branch B) — only the function
# name and includes need to be resolved.
_NAME_ONLY_SYSTEM_PROMPT = """\
You are an expert reverse engineer and C programmer.
You will be given a decompiled C function whose local variables are already
well-named. You will also receive two sections:
- "Detected Standard Library Calls": functions with already-known headers — add them to "includes".
- "Unknown External Calls": function names with no known header — infer the correct #include for each and add them to "includes".

Your jobs are:
1. Suggest a descriptive, lower_snake_case function name that reflects what the
   function actually does (e.g. 'display_main_menu', 'verify_password').
2. Write a concise 1-2 sentence technical summary of what the function does.
3. Populate "includes" with all required #include directives.

Rules:
- Do NOT rename any variables — return empty lists for variables/parameters/globals.
- Return ONLY a single valid JSON object — no markdown, no prose.

JSON schema (strict):
{
  "function_name": "<suggested_function_name>",
  "context": "<brief_summary_of_function_purpose>",
  "variables": [],
  "parameters": [],
  "globals": [],
  "includes": ["<stdio.h>"],
  "defines": [],
  "custom_types": []
}
"""

_NAME_ONLY_USER_PROMPT_TEMPLATE = """\
{callees_header}\
{strings_header}\
{builtins_header}\
{unknowns_header}\
Analyze the following decompiled C function and suggest a descriptive function name \
and a brief context summary. Return ONLY the JSON object described in the system prompt.

```c
{decompiled_c}
```
"""

# Shared empty result returned on any failure path.
_EMPTY_RESULT = {
    "function_name": None,
    "context": None,
    "variables": [],
    "parameters": [],
    "globals": [],
    "includes": [],
    "defines": [],
    "custom_types": [],
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def extract_declarations_types(c_code):
    """Parse local variable declarations to map variable names to their declared C types."""
    types = {}
    decl_re = re.compile(
        r'^\s*((?:unsigned\s+|signed\s+)?(?:int|float|double|char|long|short|bool|uint|ulong|void\s*\*|[A-Z]\w*)\s*(?:\*\s*)*)(\w+)\s*;',
        re.MULTILINE
    )
    for m in decl_re.finditer(c_code):
        t = re.sub(r'\s+', ' ', m.group(1).strip())
        types[m.group(2).strip()] = t
    return types


def _build_context_headers(callee_snippets, string_literals, detected_builtins, unknown_calls):
    """
    Build the shared prompt-section strings used by both Branch A and Branch B.

    Returns a dict with keys: callees_header, strings_header, builtins_header, unknowns_header.
    All values are either a non-empty string ending with '\\n\\n' or an empty string.
    """
    callees_header = ""
    if callee_snippets:
        callee_names = [fname for fname, _ in callee_snippets]
        callees_header = "Called Functions:\n" + "\n".join(f"- {n}" for n in callee_names) + "\n\n"

    strings_header = ""
    if string_literals:
        unique_strs = sorted(set(string_literals))[:10]
        strings_header = "Referenced String Literals:\n" + "\n".join(f'- "{s}"' for s in unique_strs) + "\n\n"

    builtins_header = ""
    if detected_builtins:
        builtins_header = (
            "Detected Standard Library Calls (use these to suggest #include directives):\n"
            + "\n".join(f"- {fn}()  \u2192  {hdr}" for fn, hdr in detected_builtins)
            + "\n\n"
        )

    unknowns_header = ""
    if unknown_calls:
        unknowns_header = (
            "Unknown External Calls (infer the correct #include for each):\n"
            + "\n".join(f"- {fn}()" for fn in unknown_calls)
            + "\n\n"
        )

    return {
        "callees_header": callees_header,
        "strings_header": strings_header,
        "builtins_header": builtins_header,
        "unknowns_header": unknowns_header,
    }


def _merge_suggestions(llm_res, builtin_suggs):
    """Merge programmatically derived builtin suggestions into LLM suggestions."""
    if not llm_res:
        llm_res = dict(_EMPTY_RESULT)

    for var, info in builtin_suggs.items():
        target_list = llm_res["parameters"] if var.startswith("param_") else llm_res["variables"]
        existing = next((v for v in target_list if v["name"] == var), None)
        if existing:
            if "new_type_str" in info and not existing.get("new_type_str"):
                existing["new_type_str"] = info["new_type_str"]
            if "new_name" in info and (not existing.get("new_name") or existing["new_name"] == var):
                existing["new_name"] = info["new_name"]
        else:
            target_list.append({
                "name": var,
                "new_name": info.get("new_name", var),
                "new_type_str": info.get("new_type_str"),
            })

    return llm_res


def _call_api(client, model, system_prompt, user_prompt):
    """
    Issue a single streaming API call.  Returns the stream object or raises.
    Handles rate-limiting with one automatic retry.
    """
    from openai import RateLimitError
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            return client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                stream=True,
                max_tokens=8192,
                temperature=0.2,
            )
        except RateLimitError as e:
            if attempt < max_attempts - 1:
                wait_time = 32
                print(f"[OpenRouter] Rate limited. Waiting {wait_time}s before retry... (Attempt {attempt+1}/{max_attempts})")
                time.sleep(wait_time)
            else:
                raise
    return None  # unreachable


def _read_stream(stream):
    """Consume a streaming API response and return the full text."""
    raw_text = ""
    for chunk in stream:
        if chunk.choices and chunk.choices[0].delta:
            delta = chunk.choices[0].delta.content
            if delta:
                raw_text += delta
    return raw_text


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def get_openrouter_suggestions(
    decompiled_c,
    model="openrouter/free",
    caller_snippets=None,
    callee_snippets=None,
    string_literals=None,
    clear_cache=False,
    # Deprecated — kept for call-site compatibility but ignored:
    context_c=None,
):
    """
    Analyse decompiled_c and return name/type suggestions via a 3-step pipeline:

      Step 2 (local): Built-in format-function analysis (scanf/printf) — no LLM.
      Step 3 (LLM, Branch A): Usage-based prompt for functions with generic vars.
      Step 3 (LLM, Branch B): Name-only prompt for functions with a generic name only.

    Returns a dict with keys: function_name, context, variables, parameters,
    globals, includes, defines, custom_types.  On any failure all lists are empty.
    """
    if not decompiled_c or not decompiled_c.strip():
        print("[OpenRouter] WARNING: empty decompiled_c, skipping.")
        return dict(_EMPTY_RESULT)

    # Pre-recover variadic arguments (e.g. scanf('%f') → scanf('%f', &local_14))
    # so the static analysis in Step 2 can see all arguments.
    from ghidra_decompiler.syntax import recover_variadic_arguments
    decompiled_c = recover_variadic_arguments(decompiled_c)

    # ── Persistent cross-binary MD5 file cache ──
    cache_dir = os.path.expanduser("~/.ghidra_ai_cache")
    code_hash = hashlib.md5(decompiled_c.strip().encode("utf-8", errors="ignore")).hexdigest()
    cache_file = os.path.join(cache_dir, f"{code_hash}.json")

    if clear_cache and os.path.exists(cache_file):
        try:
            os.remove(cache_file)
            print(f"[OpenRouter] Cache bypass flag set. Purged cache: {cache_file}")
        except Exception as e:
            print(f"[OpenRouter] Could not clear cache file: {e}")

    if not clear_cache and os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                cached = json.load(f)
            print(f"[OpenRouter] Cache HIT ({code_hash[:8]}). Bypassing API query.")
            return cached
        except Exception:
            pass

    # ── Step 2: local static analysis (no LLM) ──
    from ghidra_decompiler.builtin_suggestions import (
        extract_builtin_suggestions, extract_variable_usages,
        is_generic_or_tmp_name, get_detected_builtins, get_unknown_external_calls,
    )
    builtin_suggs   = extract_builtin_suggestions(decompiled_c)
    detected_builtins = get_detected_builtins(decompiled_c)

    known_binary_funcs = set()
    if callee_snippets:
        known_binary_funcs.update(fname for fname, _ in callee_snippets)
    if caller_snippets:
        known_binary_funcs.update(fname for fname, _ in caller_snippets)
    unknown_calls = get_unknown_external_calls(decompiled_c, known_func_names=known_binary_funcs)

    decl_types   = extract_declarations_types(decompiled_c)
    all_words    = set(re.findall(r'\b[a-zA-Z_]\w*\b', decompiled_c))
    generic_vars = [w for w in all_words if is_generic_or_tmp_name(w)]

    func_name_match = re.search(r'\b(\w+)\s*\(', decompiled_c)
    func_name       = func_name_match.group(1) if func_name_match else "unknown"
    is_func_generic = bool(
        re.match(r'^(FUN_|SUB_|thunk_)?[0-9a-fA-F]+$', func_name)
        or any(c.isdigit() for c in func_name)
    )

    def _save_cache(result):
        try:
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)
        except Exception:
            pass

    # Skip LLM entirely when nothing generic remains
    if not generic_vars and not is_func_generic:
        print(f"[OpenRouter] Skipping LLM — '{func_name}' has no generic vars or name.")
        result = _merge_suggestions(None, builtin_suggs)
        _save_cache(result)
        return result

    api_key = os.environ.get("OPEN_ROUTER_API_KEY")
    if not api_key:
        print("[OpenRouter] ERROR: OPEN_ROUTER_API_KEY not set.")
        return _merge_suggestions(None, builtin_suggs)

    try:
        from openai import OpenAI
    except ImportError:
        print("[OpenRouter] ERROR: openai not installed. Run: pip install openai")
        return _merge_suggestions(None, builtin_suggs)

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        max_retries=0,
    )

    headers = _build_context_headers(callee_snippets, string_literals, detected_builtins, unknown_calls)

    # ── Branch A: usage-based prompt (generic variables present) ──
    if generic_vars:
        var_details_list = []
        for var in sorted(generic_vars):
            t = (
                builtin_suggs[var].get("new_type_str")
                if var in builtin_suggs
                else decl_types.get(var, "unknown")
            )
            usages = extract_variable_usages(decompiled_c, var)
            if not usages:
                # Fallback: include all lines that mention the variable (incl. declaration)
                pat = re.compile(r'\b' + re.escape(var) + r'\b')
                usages = [
                    line.strip()
                    for line in decompiled_c.splitlines()
                    if pat.search(line) and line.strip()
                ]
            usage_str = "\n".join(f"    - {line}" for line in usages[:10])
            var_details_list.append(f"- Variable: {var}\n  Type: {t}\n  Usages:\n{usage_str}")

        variables_details = "\n\n".join(var_details_list)
        user_prompt = (
            headers["callees_header"]
            + headers["strings_header"]
            + headers["builtins_header"]
            + _USAGE_USER_PROMPT_TEMPLATE.format(
                variables_details=variables_details,
                unknowns_header=headers["unknowns_header"],
            )
        )
        system_prompt = _USAGE_SYSTEM_PROMPT

    # ── Branch B: name-only prompt (vars clean, function name is generic) ──
    else:
        user_prompt = _NAME_ONLY_USER_PROMPT_TEMPLATE.format(
            **headers,
            decompiled_c=decompiled_c.strip(),
        )
        system_prompt = _NAME_ONLY_SYSTEM_PROMPT

    # ── Step 3: LLM call with retry on non-JSON responses ──
    max_parse_attempts = 3
    stream = None
    try:
        stream = _call_api(client, model, system_prompt, user_prompt)
    except Exception as e:
        print(f"[OpenRouter] API call failed: {e}")
        return _merge_suggestions(None, builtin_suggs)

    raw_text = ""
    for parse_attempt in range(max_parse_attempts):
        try:
            raw_text = _read_stream(stream)
        except Exception as e:
            print(f"[OpenRouter] Error reading stream: {e}")
            return _merge_suggestions(None, builtin_suggs)

        print(f"[OpenRouter] Stream complete: {len(raw_text)} char(s) received.")

        if not raw_text.strip():
            print("[OpenRouter] WARNING: empty response from model.")
            return _merge_suggestions(None, builtin_suggs)

        if "{" not in raw_text:
            print(f"[OpenRouter] WARNING: no JSON in response (attempt {parse_attempt+1}/{max_parse_attempts}): {repr(raw_text[:100])}")
            if parse_attempt < max_parse_attempts - 1:
                try:
                    stream = _call_api(client, model, system_prompt, user_prompt)
                    continue
                except Exception as e:
                    print(f"[OpenRouter] Retry failed: {e}")
                    return _merge_suggestions(None, builtin_suggs)
            else:
                print("[OpenRouter] All attempts returned non-JSON. Giving up.")
                return _merge_suggestions(None, builtin_suggs)

        break

    res_json = _parse_suggestions(raw_text)
    res_json = _merge_suggestions(res_json, builtin_suggs)

    if res_json and any(res_json.get(k) for k in ("variables", "parameters", "function_name", "context", "custom_types")):
        _save_cache(res_json)

    return res_json


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _try_repair_truncated_json(s):
    """Append missing closing delimiters to a truncated JSON string."""
    stack = []
    in_string = False
    escaped = False
    for char in s:
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
            elif char in ('{', '['):
                stack.append(char)
            elif char in ('}', ']') and stack:
                top = stack[-1]
                if (char == '}' and top == '{') or (char == ']' and top == '['):
                    stack.pop()
    if in_string:
        s += '"'
    s = s.rstrip().rstrip(',')
    for opener in reversed(stack):
        s += '}' if opener == '{' else ']'
    return s


def _parse_suggestions(raw_text):
    """
    Extract and validate the JSON suggestions object from the LLM response.
    Handles markdown code fences and chain-of-thought prose before the JSON.
    """
    if not raw_text:
        return dict(_EMPTY_RESULT)

    # Strip markdown fences
    stripped = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.MULTILINE)
    stripped = re.sub(r"\s*```$",          "", stripped,  flags=re.MULTILINE).strip()

    # Find the outermost { ... } block
    data = None
    first_brace = stripped.find("{")
    if first_brace != -1:
        last_brace = stripped.rfind("}")
        json_candidate = (
            stripped[first_brace:last_brace + 1]
            if last_brace > first_brace
            else stripped[first_brace:]
        )
        for attempt in (json_candidate, _try_repair_truncated_json(json_candidate)):
            try:
                data = json.loads(attempt)
                break
            except json.JSONDecodeError:
                pass

    if data is None:
        for attempt in (stripped, _try_repair_truncated_json(stripped)):
            try:
                data = json.loads(attempt)
                break
            except json.JSONDecodeError as e:
                last_err = e
        else:
            print(f"[OpenRouter] JSON parse error: {last_err}")
            print(f"[OpenRouter] Raw response:\n{raw_text[:500]}")
            return dict(_EMPTY_RESULT)

    func_name    = data.get("function_name")
    context      = data.get("context")
    variables    = _sanitize_list(data.get("variables",  []), "variables")
    parameters   = _sanitize_list(data.get("parameters", []), "parameters")
    globals_list = _sanitize_list(data.get("globals",    []), "globals")
    includes     = data.get("includes",     [])
    defines      = data.get("defines",      [])
    custom_types = data.get("custom_types", [])
    if not isinstance(custom_types, list):
        print("[OpenRouter] WARNING: 'custom_types' is not a list, ignoring.")
        custom_types = []

    print(
        f"[OpenRouter] Parsed — Function='{func_name}', "
        f"{len(variables)} var(s), {len(parameters)} param(s), {len(globals_list)} global(s), "
        f"{len(custom_types)} custom_type(s), {len(includes)} inc(s), {len(defines)} def(s)"
    )
    if not func_name:
        print(f"[OpenRouter] WARNING: function_name missing. Snippet:\n{raw_text[:300]}")
    if context:
        print(f"  [OpenRouter] Context: {context}")
    for v in variables:
        print(f"  [OpenRouter] Variable:  {v.get('name')} -> {v.get('new_name')} ({v.get('new_type_str')})")
    for p in parameters:
        print(f"  [OpenRouter] Parameter: {p.get('name')} -> {p.get('new_name')} ({p.get('new_type_str')})")
    for g in globals_list:
        print(f"  [OpenRouter] Global:    {g.get('name')} -> {g.get('new_name')} ({g.get('new_type_str')})")
    for ct in custom_types:
        members = ct.get("members") or ct.get("fields") or ct.get("values") or []
        print(f"  [OpenRouter] CustomType: {ct.get('name')} ({ct.get('type')}) — {len(members)} member(s)")
    for inc in includes:
        print(f"  [OpenRouter] Include: {inc}")
    for dfn in defines:
        print(f"  [OpenRouter] Define: {dfn}")

    return {
        "function_name": func_name,
        "context":       context,
        "variables":     variables,
        "parameters":    parameters,
        "globals":       globals_list,
        "includes":      includes,
        "defines":       defines,
        "custom_types":  custom_types,
    }


def _sanitize_list(items, label):
    """
    Ensure every item in a suggestion list is a dict with 'name'.
    Malformed entries are dropped with a warning.
    """
    if not isinstance(items, list):
        print(f"[OpenRouter] WARNING: '{label}' is not a list, ignoring.")
        return []
    result = []
    for item in items:
        if not isinstance(item, dict):
            print(f"[OpenRouter] WARNING: dropping non-dict item in '{label}': {item}")
            continue
        if "name" not in item:
            print(f"[OpenRouter] WARNING: dropping item missing 'name' in '{label}': {item}")
            continue
        item.setdefault("new_name",     item["name"])
        item.setdefault("new_type_str", None)
        result.append(item)
    return result
