#@author codex
#@category Analysis

import re
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import RefType


TARGET = toAddr(0x006050D0)  # InitializeDialogTemplateFromId

fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()

refs = rm.getReferencesTo(TARGET)
callers = {}
for r in refs:
    if not r.getReferenceType().isCall():
        continue
    src = r.getFromAddress()
    fn = fm.getFunctionContaining(src)
    if fn is None:
        continue
    callers[fn.getEntryPoint()] = fn

ifc = DecompInterface()
ifc.openProgram(currentProgram)

pat_call = re.compile(r"InitializeDialogTemplateFromId\s*\(([^)]*)\)")
pat_fun = re.compile(r"FUN_006050d0\s*\(([^)]*)\)")
pat_vtable = re.compile(r"\*\s*param_1\s*=\s*&([A-Za-z0-9_]+)")

def extract_template_arg(arg_text):
    # First argument in call should be dialog template ID.
    parts = [p.strip() for p in arg_text.split(",")]
    if not parts:
        return "<unknown>"
    return parts[0]

rows = []
for ep, fn in sorted(callers.items(), key=lambda kv: int(kv[0].getOffset())):
    res = ifc.decompileFunction(fn, 30, monitor)
    if not res.decompileCompleted():
        rows.append((ep, fn.getName(), "<decompile_failed>", "<unknown>"))
        continue

    code = res.getDecompiledFunction().getC()
    call_match = pat_call.search(code)
    if call_match is None:
        call_match = pat_fun.search(code)

    if call_match is None:
        arg0 = "<not_found>"
    else:
        arg0 = extract_template_arg(call_match.group(1))

    vt_match = pat_vtable.search(code)
    vtbl = vt_match.group(1) if vt_match else "<none>"
    rows.append((ep, fn.getName(), arg0, vtbl))

print("=== callers of InitializeDialogTemplateFromId (0x006050D0) ===")
for ep, name, arg0, vtbl in rows:
    print("%s | %s | template=%s | vtbl=%s" % (ep, name, arg0, vtbl))
print("count=%d" % len(rows))
