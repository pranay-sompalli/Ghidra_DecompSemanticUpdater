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
    get_openrouter_suggestions(decompiled_c, model="openrouter/free", context_c=None) -> dict

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


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def get_openrouter_suggestions(
    decompiled_c,
    model="openrouter/free",
    context_c=None,
    caller_snippets=None,
    callee_snippets=None,
    string_literals=None,
    clear_cache=False,
):
    """
    Send decompiled_c to the OpenRouter API and return name/type suggestions.

    Parameters
    ----------
    decompiled_c : str
        Raw decompiled C code string from Ghidra's DecompInterface.
    model : str
        The OpenRouter model ID to use.  Default is "openrouter/free".
    context_c : str, optional
        Additional C code (e.g., main function) to provide as reference
        for naming and structural consistency.
    caller_snippets : list[tuple[str, str]], optional
        List of (function_name, decompiled_c) for functions that call this one.
    callee_snippets : list[tuple[str, str]], optional
        List of (function_name, decompiled_c) for functions called by this one.
    string_literals : list[str], optional
        List of string literal constants referenced inside the function body.

    Returns
    -------
    dict
        Keys: "function_name", "variables", "parameters", "globals", "includes", "defines".
        "variables", "parameters", and "globals" are lists of dicts:
            {"name": str, "new_name": str, "new_type_str": str}
        "includes" and "defines" are lists of strings.
    """
    _empty = {"function_name": None, "variables": [], "parameters": [], "globals": [], "includes": [], "defines": [], "custom_types": []}

    if not decompiled_c or not decompiled_c.strip():
        print("[OpenRouter] WARNING: empty decompiled_c, skipping.")
        return _empty

    # ── Persistent Cross-Binary MD5 File Cache Check ──
    import hashlib
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
            with open(cache_file, "r") as f:
                cached_res = json.load(f)
            print(f"[OpenRouter] Persistent Cache HIT ({code_hash[:8]}). Bypassing API query.")
            return cached_res
        except Exception:
            pass

    api_key = os.environ.get("OPEN_ROUTER_API_KEY")
    if not api_key:
        print("[OpenRouter] ERROR: OPEN_ROUTER_API_KEY not set in environment.")
        return _empty

    try:
        from openai import OpenAI, RateLimitError
    except ImportError:
        print("[OpenRouter] ERROR: openai not installed. "
            "Run: pip install openai")
        return _empty

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        max_retries=0,
    )

    context_header = ""
    if context_c:
        context_header = "REFERENCE CONTEXT (e.g., main function):\n```c\n{}\n```\n\n".format(context_c)

    callers_header = ""
    if caller_snippets:
        parts = []
        for fname, fcode in caller_snippets[:3]:  # cap at 3 to stay within token budget
            parts.append("/* caller: {} */\n{}".format(fname, fcode.strip()[:800]))
        callers_header = "CALLER FUNCTIONS (functions that call the target):\n```c\n{}\n```\n\n".format(
            "\n\n".join(parts)
        )

    callees_header = ""
    if callee_snippets:
        parts = []
        for fname, fcode in callee_snippets[:3]:  # cap at 3 to stay within token budget
            parts.append("/* callee: {} */\n{}".format(fname, fcode.strip()[:800]))
        callees_header = "CALLEE FUNCTIONS (functions called by the target):\n```c\n{}\n```\n\n".format(
            "\n\n".join(parts)
        )

    strings_header = ""
    if string_literals:
        unique_strs = sorted(list(set(string_literals)))[:10] # cap at 10 literal blocks
        strings_header = "REFERENCED STRING LITERALS:\n```c\n{}\n```\n\n".format(
            "\n".join(f'"{s}"' for s in unique_strs)
        )

    user_prompt = _USER_PROMPT_TEMPLATE.format(
        context_header=context_header,
        callers_header=callers_header,
        callees_header=callees_header,
        strings_header=strings_header,
        decompiled_c=decompiled_c.strip(),
    )

    max_attempts = 3
    stream = None
    for attempt in range(max_attempts):
        try:
            stream = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                stream=True,
                max_tokens=8192,
                temperature=0.2,
            )
            break  # Success
        except RateLimitError as e:
            if attempt < max_attempts - 1:
                wait_time = 32 # Free models often enforce 30s limits
                print(f"[OpenRouter] Rate limited. Waiting {wait_time}s before retry... (Attempt {attempt+1}/{max_attempts})")
                time.sleep(wait_time)
            else:
                print(f"[OpenRouter] API call failed after retries: {e}")
                return _empty
        except Exception as e:
            print("[OpenRouter] API call failed: {}".format(e))
            return _empty

    raw_text = ""
    for parse_attempt in range(max_attempts):
        # Collect all streamed chunks into a single response string
        raw_text = ""
        chunk_count = 0
        try:
            for chunk in stream:
                chunk_count += 1
                if chunk.choices and len(chunk.choices) > 0 and chunk.choices[0].delta:
                    delta = chunk.choices[0].delta.content
                    if delta:
                        raw_text += delta
        except Exception as e:
            print("[OpenRouter] Error reading stream: {}".format(e))
            return _empty

        print(f"[OpenRouter] Stream complete: {chunk_count} chunk(s), {len(raw_text)} char(s) received.")

        if not raw_text.strip():
            print("[OpenRouter] WARNING: Stream returned empty content. Model may have refused or timed out.")
            return _empty

        # Detect non-JSON safety/refusal responses and retry with a new API call
        if "{" not in raw_text:
            print(f"[OpenRouter] WARNING: Response contains no JSON (attempt {parse_attempt+1}/{max_attempts}): {repr(raw_text[:100])}")
            if parse_attempt < max_attempts - 1:
                print("[OpenRouter] Retrying API call...")
                try:
                    stream = client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": _SYSTEM_PROMPT},
                            {"role": "user",   "content": user_prompt},
                        ],
                        stream=True,
                        max_tokens=8192,
                        temperature=0.2,
                    )
                except Exception as e:
                    print("[OpenRouter] Retry API call failed: {}".format(e))
                    return _empty
                continue
            else:
                print("[OpenRouter] All attempts returned non-JSON responses. Giving up.")
                return _empty

        if len(raw_text) < 50:
            print(f"[OpenRouter] WARNING: Very short response: {repr(raw_text)}")

        break  # Got a response with JSON content, proceed to parse

    res_json = _parse_suggestions(raw_text)
    if res_json and (res_json.get("variables") or res_json.get("parameters") or res_json.get("function_name")):
        try:
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump(res_json, f, indent=2)
        except Exception:
            pass

    return res_json




# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _try_repair_truncated_json(s):
    """Scan a truncated JSON candidate string and append missing closing delimiters."""
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
            elif char in ('}', ']'):
                if stack:
                    top = stack[-1]
                    if (char == '}' and top == '{') or (char == ']' and top == '['):
                        stack.pop()
    if in_string:
        s += '"'
    s = s.rstrip().rstrip(',')
    for opener in reversed(stack):
        if opener == '{':
            s += '}'
        elif opener == '[':
            s += ']'
    return s


def _parse_suggestions(raw_text):
    """
    Extract and validate the JSON suggestions from the LLM response text.
    Handles cases where the model wraps JSON in markdown code fences.
    """
    _empty = {"function_name": None, "variables": [], "parameters": [], "globals": [], "includes": [], "defines": [], "custom_types": []}

    if not raw_text:
        return _empty

    # Strip markdown code fences if present (```json ... ``` or ``` ... ```)
    stripped = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.MULTILINE)
    stripped = re.sub(r"\s*```$",          "", stripped,  flags=re.MULTILINE)
    stripped = stripped.strip()

    # Models with chain-of-thought / "thinking" mode output prose before the JSON.
    # Scan for the outermost { ... } block and use that.
    data = None
    first_brace = stripped.find("{")
    if first_brace != -1:
        last_brace = stripped.rfind("}")
        if last_brace > first_brace:
            json_candidate = stripped[first_brace:last_brace + 1]
            try:
                data = json.loads(json_candidate)
            except json.JSONDecodeError:
                # Try to repair and reload
                repaired = _try_repair_truncated_json(json_candidate)
                try:
                    data = json.loads(repaired)
                except json.JSONDecodeError:
                    pass
        else:
            # Truncated before any closing brace
            json_candidate = stripped[first_brace:]
            repaired = _try_repair_truncated_json(json_candidate)
            try:
                data = json.loads(repaired)
            except json.JSONDecodeError:
                pass

    if data is None:
        # Fall back to parsing the whole stripped text (repaired if needed)
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            try:
                repaired = _try_repair_truncated_json(stripped)
                data = json.loads(repaired)
            except json.JSONDecodeError:
                print("[OpenRouter] JSON parse error: {}".format(e))
                print("[OpenRouter] Raw response was:\n{}".format(raw_text[:500]))
                return _empty

    # Validate and sanitize
    func_name  = data.get("function_name", None)
    context    = data.get("context",       None)
    variables  = _sanitize_list(data.get("variables",  []), "variables")
    parameters = _sanitize_list(data.get("parameters", []), "parameters")
    globals_list = _sanitize_list(data.get("globals", []), "globals")
    includes   = data.get("includes", [])
    defines    = data.get("defines",  [])

    custom_types = data.get("custom_types", [])
    if not isinstance(custom_types, list):
        print("[OpenRouter] WARNING: 'custom_types' is not a list, ignoring.")
        custom_types = []

    print("[OpenRouter] Suggestions — Function='{}', {} var(s), {} param(s), {} global(s), "
          "{} custom_type(s), {} inc(s), {} def(s)".format(
              func_name, len(variables), len(parameters), len(globals_list),
              len(custom_types), len(includes), len(defines)))
    if not func_name:
        print("[OpenRouter] WARNING: function_name is missing from response. Raw text snippet:\n{}".format(raw_text[:300] if raw_text else "(empty)"))
    if context:
        print("  [OpenRouter] Context: {}".format(context))

    for v in variables:
        print("  [OpenRouter] Variable: {} -> {} ({})".format(
            v.get("name"), v.get("new_name"), v.get("new_type_str")))
    for p in parameters:
        print("  [OpenRouter] Parameter: {} -> {} ({})".format(
            p.get("name"), p.get("new_name"), p.get("new_type_str")))
    for g in globals_list:
        print("  [OpenRouter] Global: {} -> {} ({})".format(
            g.get("name"), g.get("new_name"), g.get("new_type_str")))
    for ct in custom_types:
        members = ct.get("members") or ct.get("fields") or ct.get("values") or []
        print("  [OpenRouter] Custom Type: {} ({}) — {} member(s)".format(
            ct.get("name"), ct.get("type"), len(members)))
    for inc in includes:
        print("  [OpenRouter] Include: {}".format(inc))
    for dfn in defines:
        print("  [OpenRouter] Define: {}".format(dfn))

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
    Ensure every item in a suggestion list is a dict with the required keys.
    Malformed entries are dropped with a warning.
    """
    result = []
    if not isinstance(items, list):
        print("[OpenRouter] WARNING: '{}' is not a list, ignoring.".format(label))
        return result

    for item in items:
        if not isinstance(item, dict):
            print("[OpenRouter] WARNING: dropping non-dict item in '{}': {}".format(label, item))
            continue
        if "name" not in item:
            print("[OpenRouter] WARNING: dropping item missing 'name' in '{}': {}".format(label, item))
            continue
        # Supply defaults for optional fields so callers don't need to guard
        item.setdefault("new_name",     item["name"])  # keep current if not provided
        item.setdefault("new_type_str", None)          # None → don't retype
        result.append(item)

    return result
