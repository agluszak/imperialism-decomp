#@author codex
#@category Analysis

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
base = toAddr(0x00692660)
count = 32

print('=== materialize init-table function pointers @ 0x00692660 ===')
for i in range(count):
    ea = base.add(i*4)
    v = mem.getInt(ea) & 0xffffffff
    if v == 0:
        continue
    a = toAddr(v)
    fn = fm.getFunctionAt(a)
    if fn is None:
        disassemble(a)
        createFunction(a, None)
        fn = fm.getFunctionAt(a)
    print('[%02d] %s -> %s' % (i, ea, fn.getName() if fn else '<create_failed>'))
