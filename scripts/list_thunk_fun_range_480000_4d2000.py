#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
start = toAddr(0x00480000)
end_off = 0x004D2000

print("=== thunk_FUN_* in range 0x00480000-0x004D2000 ===")
count = 0
it = fm.getFunctions(start, True)
while it.hasNext():
    fn = it.next()
    off = fn.getEntryPoint().getOffset()
    if off >= end_off:
        break
    name = fn.getName()
    if name.startswith("thunk_FUN_"):
        print('%s %s' % (fn.getEntryPoint(), name))
        count += 1
print('count=%d' % count)
