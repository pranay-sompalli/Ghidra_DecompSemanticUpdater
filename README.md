# Ghidra DecompSemanticUpdater

An AI-enhanced Ghidra decompilation pipeline that uses the **Cerebras Cloud API**
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
    └── cerebras.py         ← Cerebras Cloud SDK & Prompting
```

---

## Requirements

- Python ≥ 3.9
- **Ghidra** installation with **PyGhidra** configured
- **Cerebras Cloud API key** exported as `CEREBRAS_API_KEY`

Installation:

```bash
pip install -r requirements.txt
```

---

## Usage

1. Set your Cerebras API key:
   ```bash
   export CEREBRAS_API_KEY="your-key-here"
   ```

2. Run the pipeline:
   ```bash
   python scripts/decompile_binary.py <binary_name>
   ```

   **Example:**
   ```bash
   python scripts/decompile_binary.py crackme0x06
   ```

---

## Pipeline Overview

| Pass | Description |
|------|-------------|
| **Pre-pass** | Decompiles `main` to establish a global reference context for LLM consistency. |
| **Pass 1 & 2** | **(Iterative)** Detects return types and commits initial metadata. Queries Cerebras for suggestions. If new generic variables spawn (due to data-flow splitting), it performs a second AI pass to capture them. |
| **Comments** | AI-generated function summaries are applied as header comments directly to the Ghidra database. |
| **Passes 3 & 4** | **Global Alignment**: Propagates naming improvements deep into the call tree (callees ↔ callers). |
| **Final** | Re-decompiles all functions with full semantic context, sanitizes code (hex → decimal, bool → int), and writes output to `output/`. |

---

## Supported Cerebras Models

| Model ID | Notes |
|----------|-------|
| `llama3.1-8b` | Default — Fastest response |
| `qwen-3-235b-a22b-instruct-2507` | Highest quality inference |
| `gpt-oss-120b` | Large context alternative |