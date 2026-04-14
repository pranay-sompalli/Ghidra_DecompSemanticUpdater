# Ghidra DecompSemanticUpdater

An AI-enhanced Ghidra decompilation pipeline that uses the **Cerebras Cloud API**
to automatically assign semantically meaningful variable names, parameter names,
and C types to Ghidra-decompiled pseudocode.

---

## Project Structure

```
ghidra_decompiler/          ← main Python package
├── __init__.py             ← public API re-exports
├── pipeline.py             ← top-level orchestrator (enhance_decompilation_with_ai)
├── semantics.py            ← Ghidra function/variable semantic update helpers
├── type_utils.py           ← C type string → Ghidra DataType resolution
├── code_utils.py           ← C code sanitization, name inspection
├── alignment.py            ← cross-function naming alignment pass
├── core_functions.py       ← BFS collection of reachable user functions
├── find_main.py            ← multi-strategy main() locator
└── ai/
    ├── __init__.py
    └── cerebras.py         ← Cerebras Cloud API integration

scripts/
└── decompile_binary.py     ← runnable entry-point script

output/                     ← generated decompiled .c files (git-ignored)
```

---

## Requirements

- Python ≥ 3.9
- A working **Ghidra** installation with **PyGhidra** configured
- A **Cerebras Cloud API key** exported as `CEREBRAS_API_KEY`

Install Python dependencies:

```bash
pip install -r requirements.txt
# or
pip install cerebras-cloud-sdk pyghidra
```

---

## Usage

1. Set your Cerebras API key:

   ```bash
   export CEREBRAS_API_KEY="your-key-here"
   ```

2. Edit `BINARY_PATH` in `scripts/decompile_binary.py` (or set the `BINARY_PATH`
   environment variable) to point at the binary you want to decompile.

3. Run the pipeline:

   ```bash
   python scripts/decompile_binary.py
   ```

   The sanitized, AI-enhanced C output is written to `output/<binary_name>_decompiled.c`.

---

## Pipeline Overview

| Pass | What happens |
|------|-------------|
| Pre-pass | Decompile `main` to use as naming reference context for the LLM |
| Pass 1 | Detect return types via P-Code; commit params/locals to Ghidra DB; query Cerebras for name/type suggestions |
| Pass 2 | Apply all AI suggestions (function names, variable names, types) |
| Passes 3–4 | Two-round cross-function alignment: propagate good names from callers to callees and vice-versa |
| Final | Re-decompile all functions, sanitize C code (hex → decimal, bool → int), write output |

---

## Supported Cerebras Models

| Model ID | Notes |
|----------|-------|
| `llama3.1-8b` | Default — fastest |
| `qwen-3-235b-a22b-instruct-2507` | High quality |
| `gpt-oss-120b` | Alternative large model |

Pass a different model via `enhance_decompilation_with_ai(..., model="<id>")`.