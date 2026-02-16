#@author codex
#@category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
fm=currentProgram.getFunctionManager(); ifc=DecompInterface(); ifc.openProgram(currentProgram); mon=ConsoleTaskMonitor()

targets=[0x00413d20,0x004851b0,0x00485920,0x005d7240]
for t in targets:
    fn=fm.getFunctionContaining(toAddr(t))
    if not fn: continue
    res=ifc.decompileFunction(fn,60,mon)
    if not res.decompileCompleted():
        print('failed',hex(t)); continue
    c=res.getDecompiledFunction().getC()
    print('===',fn.getName(),hex(t),'===')
    for line in c.split('\n'):
        l=line.lower()
        if '+ 0x4c' in l or 'dispatchglobalturneventcode' in l or '0x3b6' in l or 'wparam' in l or 'getitemdata' in l:
            print(line)
    print('')
