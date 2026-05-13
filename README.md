# Ghidra DecompSemanticUpdater

An AI-enhanced Ghidra decompilation pipeline that uses the **OpenRouter API**
to automatically assign semantically meaningful variable names, parameter names,
C types, and high-level purpose comments to Ghidra-decompiled pseudocode.

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
├── find_main.py            ← robust main() locator (entry vs. start)
└── ai/
    ├── __init__.py
    └── openrouter.py       ← OpenRouter SDK & Prompting
```

---

## Requirements

- Python ≥ 3.9
- **Ghidra** installation with **PyGhidra** configured
- **OpenRouter API key** exported as `OPEN_ROUTER_API_KEY`

Installation:

```bash
pip install -r requirements.txt
```

---

## Usage

1. Set your OpenRouter API key:
   ```bash
   export OPEN_ROUTER_API_KEY="your-key-here"
   ```

2. Run the pipeline:
   ```bash
   python scripts/decompile_binary.py <binary_name> [--model <model_id>]
   ```

   **Example:**
   ```bash
   python scripts/decompile_binary.py crackme0x06
   python scripts/decompile_binary.py banking_normal --model qwen/qwen3-coder:free
   ```

---

## Pipeline Overview

| Pass | Description |
|------|-------------|
| **Pre-pass** | Decompiles `main` to establish a global reference context for LLM consistency. |
| **Pass 1 & 2** | **(Iterative)** Detects return types and commits initial metadata. Queries OpenRouter for suggestions. If new generic variables spawn (due to data-flow splitting), it performs a second AI pass to capture them. |
| **Comments** | AI-generated function summaries are applied as header comments directly to the Ghidra database. |
| **Passes 3 & 4** | **Global Alignment**: Propagates naming improvements deep into the call tree (callees ↔ callers). |
| **Final** | Re-decompiles all functions with full semantic context, sanitizes code (hex → decimal, bool → int), and writes output to `output/`. |

---

## Supported OpenRouter Models

| Model ID | Notes |
|----------|-------|
| `qwen/qwen3-coder:free` | Default — Fast & Free coder model |
| `meta-llama/llama-3.3-70b-instruct:free` | High quality inference |
| `openai/gpt-oss-120b:free` | Large context alternative |
| `openrouter/free` | Auto-routing to a free model |