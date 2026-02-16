#@author codex
#@category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

fm=currentProgram.getFunctionManager()
ifc=DecompInterface(); ifc.openProgram(currentProgram); mon=ConsoleTaskMonitor()

print('=== decompile scan for literal 0x3B6 in function text (limited) ===')
count=0
for fn in fm.getFunctions(True):
    name=fn.getName()
    if not (name.startswith('Build') or name.startswith('Handle') or name.startswith('Dispatch') or name.startswith('FUN_')):
        continue
    ep=fn.getEntryPoint().getOffset()
    if ep < 0x00400000 or ep > 0x00630000:
        continue
    res=ifc.decompileFunction(fn,20,mon)
    if not res.decompileCompleted():
        continue
    c=res.getDecompiledFunction().getC().lower()
    if '0x3b6' in c:
        print('%s | %s' % (fn.getEntryPoint(), name))
        count+=1
        if count>=30:
            break
print('TOTAL_SHOWN=%d' % count)
