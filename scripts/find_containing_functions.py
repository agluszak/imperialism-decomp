#@author codex
#@category Analysis

targets = [
    "0x005a203c",
    "0x005a215d",
    "0x005a3529",
    "0x005a35e1",
]

fm = currentProgram.getFunctionManager()
for s in targets:
    addr = toAddr(s)
    fn = fm.getFunctionContaining(addr)
    if fn is None:
        print("%s -> <no containing function>" % s)
    else:
        print("%s -> %s @ %s" % (s, fn.getName(), fn.getEntryPoint().toString()))
