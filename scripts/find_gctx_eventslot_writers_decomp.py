#@author codex
#@category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

fm = currentProgram.getFunctionManager()
refman = currentProgram.getReferenceManager()

target = toAddr(0x006a21bc)
refs = list(refman.getReferencesTo(target))
funcs = {}
for r in refs:
    fn = fm.getFunctionContaining(r.getFromAddress())
    if fn:
        funcs[fn.getEntryPoint()] = fn

ifc = DecompInterface()
ifc.openProgram(currentProgram)
mon = ConsoleTaskMonitor()

patterns = ['g_pUiRuntimeContext + 4', 'g_pUiRuntimeContext[1]', '*(short *)(g_pUiRuntimeContext + 4)']

print('=== potential writers to g_pUiRuntimeContext event slot ===')
for ep, fn in sorted(funcs.items(), key=lambda kv: kv[0].getOffset()):
    try:
        res = ifc.decompileFunction(fn, 30, mon)
        if not res.decompileCompleted():
            continue
        c = res.getDecompiledFunction().getC()
    except Exception:
        continue

    hit = False
    lines = []
    for line in c.split('\n'):
        low = line.lower()
        if any(p.lower() in low for p in patterns):
            if '=' in line and '==' not in line:
                hit = True
                lines.append(line.strip())
    if hit:
        print('%s | %s' % (fn.getEntryPoint(), fn.getName()))
        for l in lines[:6]:
            print('  ' + l)

print('=== done ===')
