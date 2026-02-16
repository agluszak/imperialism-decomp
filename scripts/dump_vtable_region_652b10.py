#@author codex
#@category Analysis

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()

base = toAddr(0x00652B10)
count = 32

print("=== vtable-ish region near 0x00652B10 ===")
for i in range(count):
    ea = base.add(i * 4)
    try:
        ptr = mem.getInt(ea) & 0xffffffff
    except Exception as ex:
        print("[%02d] %s | <read_fail: %s>" % (i, ea, ex))
        continue
    tgt = toAddr(ptr)
    fn = fm.getFunctionAt(tgt)
    name = fn.getName() if fn else "<no_function>"
    print("[%02d] %s -> %08x (%s)" % (i, ea, ptr, name))
