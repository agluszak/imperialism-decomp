#@author codex
#@category Analysis

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()
base = toAddr(0x00692660)
count = 32

print('=== check init table names @ 0x00692660 ===')
remaining = 0
for i in range(count):
    ea = base.add(i*4)
    v = mem.getInt(ea) & 0xffffffff
    if v == 0:
        continue
    fn = fm.getFunctionAt(toAddr(v))
    name = fn.getName() if fn else '<no_function>'
    bad = name.startswith('FUN_') or name.startswith('thunk_FUN_') or name == '<no_function>'
    if bad:
        remaining += 1
    print('[%02d] %08x %s %s' % (i, v, 'BAD' if bad else 'OK ', name))
print('remaining=%d' % remaining)
