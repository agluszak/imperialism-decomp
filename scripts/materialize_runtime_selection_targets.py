#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
addrs = [0x005e2b50,0x005e2b70,0x0047fd70,0x004804c0,0x00480820,0x005e2bb0]
for x in addrs:
    a = toAddr(x)
    fn = fm.getFunctionContaining(a)
    if fn is None:
        fn = createFunction(a, None)
        print('CREATE %s -> %s' % (a, fn.getName() if fn else 'None'))
    else:
        print('EXIST  %s -> %s' % (a, fn.getName()))
