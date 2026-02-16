#@author codex
#@category Analysis

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

fm=currentProgram.getFunctionManager()
ifc=DecompInterface(); ifc.openProgram(currentProgram); mon=ConsoleTaskMonitor()

for addr in [0x005d7240,0x004357b0,0x005d6b70,0x005d69b0]:
    fn=fm.getFunctionContaining(toAddr(addr))
    if not fn: continue
    res=ifc.decompileFunction(fn,60,mon)
    if not res.decompileCompleted():
        print('fail',fn.getName()); continue
    c=res.getDecompiledFunction().getC().lower()
    print('===',fn.getName(),hex(addr),'===')
    for line in c.split('\n'):
        if '0x3b6' in line:
            print('  '+line.strip())
