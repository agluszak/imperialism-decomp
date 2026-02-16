#@author codex
#@category Analysis

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
base = toAddr(0x00692660)
count = 24

print('=== dword table near 0x00692660 ===')
for i in range(count):
    ea = base.add(i*4)
    v = mem.getInt(ea) & 0xffffffff
    tgt = toAddr(v)
    fn = fm.getFunctionAt(tgt)
    name = fn.getName() if fn else '<no_function>'
    print('[%02d] %s -> %08x (%s)' % (i, ea, v, name))
