# Ghidra DecompSemanticUpdater 🚀

An advanced, production-ready **universal AI-enhanced binary decompilation framework** that leverages Large Language Models (via OpenRouter) to automatically assign semantically meaningful variable names, function parameters, precise C types, global data definitions, and high-level contextual summaries to stripped binaries — across **any major binary format and CPU architecture**.

---

## 🌍 Universal Binary Support

| Format | OS | Architectures |
|---|---|---|
| **ELF** | Linux, BSD, bare-metal | x86, x86-64, ARM32, ARM64, MIPS, RISC-V |
| **Mach-O** | macOS, iOS | ARM64 (Apple Silicon), x86-64 (Intel) |
| **PE** | Windows | x86, x86-64 |

The pipeline **auto-detects** the binary format and architecture at runtime and adapts every stage — entry-point resolution, section filtering, boilerplate exclusion, type aliases, and calling-convention stripping — without any manual configuration.

---

## 🔥 First-Class Capabilities

* **🔍 Format-Aware Platform Detection**
  A dedicated `platform_utils` module is the single source of truth for all format/architecture decisions. Running the same command on a Linux ELF, a macOS ARM64 Mach-O, or a Windows PE binary just works — no flags, no config changes.

* **🧠 Multi-Threaded Parallel Inference Engine**
  Bypasses synchronous decompiler bottlenecks by orchestrating LLM queries asynchronously across a bounded `ThreadPoolExecutor` worker pool, scaling inference speeds dramatically.

* **💾 Persistent Cross-Binary MD5 Cache**
  Canonically hashes each decompiled function body and persists AI responses to `~/.ghidra_ai_cache/`. Identical library functions in different binaries load at zero API cost.

* **🎯 Embedded String Literal Prompt Enrichment**
  Programmatically extracts referenced C-string constants and injects them as high-fidelity naming priors into the LLM prompt, slashing hallucination rates for opaque control flows.

* **🔗 4-Phase Call-Graph Discovery Engine**
  Multi-seeded BFS → hybrid complexity/density filter → priority scoring → Kahn's topological sort. Processes callees before callers so each LLM call has the richest possible context.

* **↔️ Bidirectional Cross-Function Name Alignment**
  Two-pass propagation pushes names and types both caller→callee and callee→caller, capturing multi-level naming chains that single-pass approaches miss.

* **🌐 Semantic Global Variable Typing**
  Scans format-aware data sections to re-type Ghidra primitives (`undefined4`) from how they are used in the code (e.g., passed to `scanf("%f")` → typed as `float`).

* **🖥️ Live Ghidra GUI Plugin**
  Run the full pipeline natively in Ghidra CodeBrowser. Applies `_tmp_N` P-Code remappings live in the UI without a separate headless run.

---

## 📂 Architecture & Package Organisation

```text
ReverseEngineeringProject/
├── ghidra_decompiler/          ← Core engine framework
│   ├── platform_utils.py       ← Universal format/arch detection (NEW)
│   ├── pipeline.py             ← Parallel DAG orchestrator & thread pool
│   ├── semantics.py            ← Symbol renames & global type commits
│   ├── type_utils.py           ← Type parsing & Ghidra DataType resolution
│   ├── code_utils.py           ← 12-pass C source sanitizer
│   ├── alignment.py            ← Bidirectional inter-procedural alignment
│   ├── core_functions.py       ← 4-Phase BFS discovery engine
│   ├── find_main.py            ← Format-aware entry-point resolver
│   ├── syntax.py               ← Variadic argument recovery (scanf)
│   ├── gui_utils/
│   │   └── optimizer.py        ← Live GUI temporary-name suppressor
│   └── ai/
│       └── openrouter.py       ← OpenRouter client, MD5 cache & prompts
├── scripts/
│   ├── decompile_binary.py     ← Headless CLI pipeline driver
│   └── GhidraAIPipeline.py     ← Native Ghidra GUI runner
└── output/                     ← Compiler-ready C source output
```

---

## ⚡ Installation & Workspace Configuration

### Prerequisites
- **Python 3.9+**
- **Ghidra 11.0+** with **PyGhidra** initialized
- **OpenRouter API Key** — free-tier models work for most binaries

### Setup
```bash
pip install -r requirements.txt
export OPEN_ROUTER_API_KEY="sk-or-v1-..."
```

---

## 🛠️ Unified Execution Workflows

### Option A: Headless CLI — Any Binary, Any Format

Drop any binary (ELF, Mach-O, PE) into `binaries/` and run:

```bash
python scripts/decompile_binary.py <binary_name> [--model <model_id>]
```

**Examples:**
```bash
# Linux ELF (32-bit x86)
python scripts/decompile_binary.py crackme0x06

# macOS Mach-O (ARM64 Apple Silicon)
python scripts/decompile_binary.py banking_normal --model qwen/qwen3-coder:free

# Windows PE (x86-64)
python scripts/decompile_binary.py setup.exe --model meta-llama/llama-3.3-70b-instruct:free
```

The pipeline auto-detects format and architecture. Output is written to `output/<binary>_decompiled.c`.

### Option B: Native Ghidra GUI CodeBrowser

1. Open Ghidra's **Script Manager**
2. Run `scripts/GhidraAIPipeline.py` (keybinding: `Ctrl + Alt + A`)
3. If credentials are not exported, a dialog prompts for your API key
4. Variable names, parameter types, global types, and function summaries populate automatically

---

## 📊 Pipeline Processing Stages

| Stage | Operation |
|-------|-----------|
| **Platform** | Detect ELF / Mach-O / PE and CPU architecture; set format-aware section names, noise symbols, boilerplate regex, type map |
| **Stage A** | Sequential `DecompInterface` extraction — canonical C strings, caller/callee snippets, string literal primes |
| **Stage B** | Parallel `ThreadPoolExecutor` dispatch — OpenRouter queries or instant MD5 cache loads |
| **Stage C** | Ghidra DB semantic commits — variable renames, parameter updates, global retypes, function docstrings |
| **Stage D** | 2-pass bidirectional alignment — caller↔callee naming and type propagation |
| **Stage E** | 12-pass C sanitization + arch-aware calling-convention strip → compiler-ready output |

---

## 🌟 Verified Model Profiles

| Model ID | Best For | Cost |
|---|---|---|
| `qwen/qwen3-coder:free` | Default — fast code-specialized backbone | Free |
| `meta-llama/llama-3.3-70b-instruct:free` | Complex control-flow & multi-function reasoning | Free |
| `openai/gpt-4o-mini` | High accuracy baseline for benchmarking | Paid |
| `openrouter/free` | Auto-route to fastest available free model | Free |

---