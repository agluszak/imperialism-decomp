#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
addr = toAddr(0x004a9990)
fn = fm.getFunctionContaining(addr)
if fn is None:
    fn = createFunction(addr, None)
    print('CREATED', fn.getName() if fn else '<failed>', fn.getEntryPoint() if fn else '')
else:
    print('EXISTS', fn.getName(), fn.getEntryPoint())
