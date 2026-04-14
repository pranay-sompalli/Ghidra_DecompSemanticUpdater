# A Ghidra python script to print variable types
import ghidra.app.decompiler.DecompInterface as DecompInterface
from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor
import __main__ as ghidra_app
program = ghidra_app.currentProgram

def run():
    if not program:
        print("No program")
        return
        
    main_func = None
    for f in program.getFunctionManager().getFunctions(True):
        if f.getName() == "main":
            main_func = f
            break
            
    if not main_func:
        return
        
    for var in main_func.getAllVariables():
        if "local_7c" in var.getName() or "password" in var.getName():
            print("Variable:", var.getName())
            dt = var.getDataType()
            print("  Type name:", dt.getName())
            print("  Type class:", dt.getClass().getName())
            
            temp = dt
            for _ in range(5):
                if hasattr(temp, "getDataType") and temp.getDataType() is not None:
                    temp = temp.getDataType()
                    print("  Resolved name:", temp.getName())
                    print("  Resolved class:", temp.getClass().getName())
                else:
                    break

run()
