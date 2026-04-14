"""
cerebras_suggestions.py
-----------------------
Uses Cerebras AI API (model: llama3.1-8b) to suggest semantically
meaningful variable names/types and parameter names/types for a decompiled
C function.

Note: gpt-oss-120b and qwen-3-235b-a22b-instruct-2507 are other options, 
but llama3.1-8b is the default.

Environment variable required:
    CEREBRAS_API_KEY  — your Cerebras Cloud API key

Public API:
    get_cerebras_suggestions(decompiled_c: str) -> dict

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
            "defines": ["#define MAX_SIZE 256"]
        }

    On any failure the function returns a dict with empty lists for the keys so
    the caller can always iterate safely.
"""

import os
import json
import re

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert reverse engineer and C programmer. \
You will be given raw decompiled C pseudocode produced by Ghidra. \
Your job is to infer the most semantically accurate names and C types for \
every local variable and every function parameter visible in the code.

Rules:
- Only suggest names/types for identifiers that APPEAR in the provided code.
- Do NOT invent variables that are not present.
- Analyze what the function does and suggest a descriptive function name (e.g., 'verify_password' instead of 'check').
- Use standard C type strings: "int", "unsigned int", "long", "char",
  "char *", "char **", "void *", "void", "float", "double",
  "unsigned char", "short", "unsigned short".
- Prefer descriptive, lower_snake_case names (e.g. "buffer_size", "file_ptr").
- If a variable or parameter already has a reasonable name, you may keep it
  (omit from the list or repeat the same name).
- Suggest any necessary standard C headers (as #include directives, e.g. "<stdio.h>") and any necessary #define macros or constants that the code might rely on to successfully compile.
- Return ONLY a single valid JSON object — no markdown, no prose.

JSON schema (strict):
{
  "function_name": "<new_function_name>",
  "variables": [
    {"name": "<current_name>", "new_name": "<suggested_name>", "new_type_str": "<c_type>"}
  ],
  "parameters": [
    {"name": "<current_name>", "new_name": "<suggested_name>", "new_type_str": "<c_type>"}
  ],
  "includes": [
    "<stdio.h>",
    "<stdlib.h>"
  ],
  "defines": [
    "#define MAX_BUFFER 1024"
  ]
}
"""

_USER_PROMPT_TEMPLATE = """\
{context_header}
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

def get_cerebras_suggestions(decompiled_c, model="llama3.1-8b", context_c=None):
    """
    Send decompiled_c to the Cerebras API and return name/type suggestions.

    Parameters
    ----------
    decompiled_c : str
        Raw decompiled C code string from Ghidra's DecompInterface.
    model : str
        The model ID to use for suggestions. 
        Default is "llama3.1-8b".
    context_c : str, optional
        Additional C code (e.g., main function) to provide as reference 
        for naming and structural consistency.

    Returns
    -------
    dict with keys "variables", "parameters", "includes", and "defines".
        "variables" and "parameters" are lists of dicts: {"name": str, "new_name": str, "new_type_str": str}
        "includes" and "defines" are lists of strings.
    """
    _empty = {"variables": [], "parameters": [], "includes": [], "defines": []}

    api_key = os.environ.get("CEREBRAS_API_KEY")
    if not api_key:
        print("[Cerebras] ERROR: CEREBRAS_API_KEY not set in environment.")
        return _empty

    if not decompiled_c or not decompiled_c.strip():
        print("[Cerebras] WARNING: empty decompiled_c, skipping.")
        return _empty

    try:
        from cerebras.cloud.sdk import Cerebras
    except ImportError:
        print("[Cerebras] ERROR: cerebras-cloud-sdk not installed. "
              "Run: pip install cerebras-cloud-sdk")
        return _empty

    client = Cerebras(api_key=api_key)

    context_header = ""
    if context_c:
        context_header = "REFERENCE CONTEXT (e.g., main function):\n```c\n{}\n```\n\n".format(context_c)

    user_prompt = _USER_PROMPT_TEMPLATE.format(
        context_header=context_header,
        decompiled_c=decompiled_c.strip()
    )

    try:
        stream = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            stream=True,
            max_tokens=2048,
            temperature=0.2,
        )
    except Exception as e:
        print("[Cerebras] API call failed: {}".format(e))
        return _empty

    # Collect all streamed chunks into a single response string
    raw_text = ""
    try:
        for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                raw_text += delta
    except Exception as e:
        print("[Cerebras] Error reading stream: {}".format(e))
        return _empty

    return _parse_suggestions(raw_text)



# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_suggestions(raw_text):
    """
    Extract and validate the JSON suggestions from the LLM response text.
    Handles cases where the model wraps JSON in markdown code fences.
    """
    _empty = {"variables": [], "parameters": [], "includes": [], "defines": []}

    if not raw_text:
        return _empty

    # Strip markdown code fences if present (```json ... ``` or ``` ... ```)
    stripped = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.MULTILINE)
    stripped = re.sub(r"\s*```$",          "", stripped,  flags=re.MULTILINE)
    stripped = stripped.strip()

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as e:
        print("[Cerebras] JSON parse error: {}".format(e))
        print("[Cerebras] Raw response was:\n{}".format(raw_text))
        return _empty

    # Validate and sanitize
    func_name  = data.get("function_name", None)
    variables  = _sanitize_list(data.get("variables",  []), "variables")
    parameters = _sanitize_list(data.get("parameters", []), "parameters")
    includes   = data.get("includes", [])
    defines    = data.get("defines", [])

    print("[Cerebras] Suggestions — Function='{}', {} variable(s), {} parameter(s), {} include(s), {} define(s)".format(
        func_name, len(variables), len(parameters), len(includes), len(defines)))
        
    for v in variables:
        print("  [Cerebras] Variable: {} -> {} ({})".format(v.get("name"), v.get("new_name"), v.get("new_type_str")))
    for p in parameters:
        print("  [Cerebras] Parameter: {} -> {} ({})".format(p.get("name"), p.get("new_name"), p.get("new_type_str")))
    for inc in includes:
        print("  [Cerebras] Include: {}".format(inc))
    for dfn in defines:
        print("  [Cerebras] Define: {}".format(dfn))

    return {
        "function_name": func_name, 
        "variables": variables, 
        "parameters": parameters,
        "includes": includes,
        "defines": defines
    }


def _sanitize_list(items, label):
    """
    Ensure every item in a suggestion list is a dict with the required keys.
    Malformed entries are dropped with a warning.
    """
    result = []
    if not isinstance(items, list):
        print("[Cerebras] WARNING: '{}' is not a list, ignoring.".format(label))
        return result

    for item in items:
        if not isinstance(item, dict):
            print("[Cerebras] WARNING: dropping non-dict item in '{}': {}".format(
                label, item))
            continue
        if "name" not in item:
            print("[Cerebras] WARNING: dropping item missing 'name' in '{}': {}".format(
                label, item))
            continue
        # Supply defaults for optional fields so callers don't need to guard
        item.setdefault("new_name",     item["name"])   # keep current if not provided
        item.setdefault("new_type_str", None)           # None → don't retype
        result.append(item)

    return result
