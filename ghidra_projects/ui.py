import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import threading
import subprocess
import sys
import os

class DecompilerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Binary Decompiler")
        self.root.geometry("900x650")
        self.root.configure(bg="#1e1e2e")

        self._build_header()
        self._build_file_row()
        self._build_output()
        self._build_status()

    def _build_header(self):
        header = tk.Frame(self.root, bg="#1e1e2e")
        header.pack(fill="x", padx=20, pady=(18, 4))
        tk.Label(
            header, text="⚙ Binary Decompiler", font=("SF Pro Display", 20, "bold"),
            fg="#cba6f7", bg="#1e1e2e"
        ).pack(side="left")

    def _build_file_row(self):
        frame = tk.Frame(self.root, bg="#313244", bd=0, highlightthickness=0)
        frame.pack(fill="x", padx=20, pady=8)

        inner = tk.Frame(frame, bg="#313244")
        inner.pack(fill="x", padx=12, pady=10)

        tk.Label(inner, text="Binary:", fg="#cdd6f4", bg="#313244",
                 font=("SF Pro Text", 12)).pack(side="left")

        self.path_var = tk.StringVar(value="No file selected")
        self.path_label = tk.Label(
            inner, textvariable=self.path_var, fg="#a6e3a1", bg="#313244",
            font=("SF Mono", 11), anchor="w"
        )
        self.path_label.pack(side="left", fill="x", expand=True, padx=(8, 12))

        self.browse_btn = tk.Button(
            inner, text="Browse…", command=self._browse,
            bg="#cba6f7", fg="#1e1e2e", font=("SF Pro Text", 11, "bold"),
            relief="flat", cursor="hand2", padx=14, pady=4
        )
        self.browse_btn.pack(side="left")

        self.run_btn = tk.Button(
            inner, text="▶  Decompile", command=self._run,
            bg="#a6e3a1", fg="#1e1e2e", font=("SF Pro Text", 11, "bold"),
            relief="flat", cursor="hand2", padx=14, pady=4,
            state="disabled"
        )
        self.run_btn.pack(side="left", padx=(8, 0))

    def _build_output(self):
        frame = tk.Frame(self.root, bg="#1e1e2e")
        frame.pack(fill="both", expand=True, padx=20, pady=(4, 0))

        tk.Label(frame, text="Decompiled Output", fg="#89b4fa", bg="#1e1e2e",
                 font=("SF Pro Text", 11, "bold")).pack(anchor="w", pady=(0, 4))

        self.output = scrolledtext.ScrolledText(
            frame, bg="#181825", fg="#cdd6f4", insertbackground="#cdd6f4",
            font=("SF Mono", 11), relief="flat", wrap="word",
            selectbackground="#45475a"
        )
        self.output.pack(fill="both", expand=True)
        self.output.config(state="disabled")

    def _build_status(self):
        self.status_var = tk.StringVar(value="Ready")
        bar = tk.Frame(self.root, bg="#181825")
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.status_var, fg="#6c7086", bg="#181825",
                 font=("SF Pro Text", 10), anchor="w", padx=12, pady=4).pack(fill="x")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select binary",
            initialdir=os.path.expanduser("~/Downloads")
        )
        if path:
            self.binary_path = path
            self.path_var.set(path)
            self.run_btn.config(state="normal")
            self.status_var.set(f"Selected: {os.path.basename(path)}")

    def _run(self):
        self.run_btn.config(state="disabled")
        self.browse_btn.config(state="disabled")
        self._set_output("")
        self.status_var.set("Running decompiler…")
        threading.Thread(target=self._decompile_thread, daemon=True).start()

    def _decompile_thread(self):
        # Patch binary_path in decompile_binary.py dynamically via env / subprocess
        script = os.path.join(os.path.dirname(__file__), "_run_decompiler.py")
        self._write_runner(script)

        proc = subprocess.Popen(
            [sys.executable, script],
            cwd=os.path.dirname(__file__),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        buf = []
        for line in proc.stdout:
            buf.append(line)
            # stream output into the text widget
            self.root.after(0, self._append_output, line)

        proc.wait()
        self.root.after(0, self._done, proc.returncode)

    def _write_runner(self, path):
        """Write a one-off runner script that injects the chosen binary path."""
        script = f"""
import sys, os
sys.path.insert(0, {repr(os.path.dirname(__file__))})

import pyghidra
from update_semantics import update_entry_semantics, strip_leading_underscores
from coreFunctions import getCoreFunctions

binary_path = {repr(self.binary_path)}

pyghidra.start()

from java.io import File
builder = pyghidra.program_loader()
builder.source(File(binary_path))
results = builder.load()
if not results:
    print("Failed to load program.")
    sys.exit(1)

res = next(iter(results))
program = res.getDomainObject()
pyghidra.api.analyze(program)
strip_leading_underscores(program)

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

iface = DecompInterface()
iface.openProgram(program)

fm = program.getFunctionManager()
coreFunctions = {{}}
for func in fm.getFunctions(True):
    if func.isThunk() or func.isExternal() or func.isLibrary() or func.isInline():
        continue
    block = func.getProgram().getMemory().getBlock(func.getEntryPoint())
    if block and block.getName() == ".text":
        coreFunctions[func.getName()] = func

for name, func in getCoreFunctions(coreFunctions).items():
    update_entry_semantics(program, func)
    print(f"\\n/* --- Function: {{name}} --- */")
    dec = iface.decompileFunction(func, 30, ConsoleTaskMonitor())
    if dec.decompileCompleted():
        print(dec.getDecompiledFunction().getC())

res.release(None)
"""
        with open(path, "w") as f:
            f.write(script)

    def _set_output(self, text):
        self.output.config(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", text)
        self.output.config(state="disabled")

    def _append_output(self, text):
        self.output.config(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.config(state="disabled")

    def _done(self, code):
        self.run_btn.config(state="normal")
        self.browse_btn.config(state="normal")
        if code == 0:
            self.status_var.set("✓ Done")
        else:
            self.status_var.set(f"✗ Exited with code {code}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DecompilerUI(root)
    root.mainloop()
