#@author codex
#@category Analysis

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()

base = toAddr(0x00652A80)
count = 24

print("=== vtable-ish region near 0x00652A80 ===")
for i in range(count):
    ea = base.add(i * 4)
    try:
        ptr = mem.getInt(ea) & 0xffffffff
    except:
        print("%s | <read_fail>" % ea)
        continue
    tgt = toAddr(ptr)
    fn = fm.getFunctionAt(tgt)
    name = fn.getName() if fn else "<no_function>"
    print("[%02d] %s -> %08x (%s)" % (i, ea, ptr, name))
