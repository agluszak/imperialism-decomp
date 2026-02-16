#@author codex
#@category Analysis

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()

regions = [
    (0x006528D8, 32, "0x006528D8"),
    (0x00652B10, 32, "0x00652B10"),
    (0x00652D60, 32, "0x00652D60"),
]

for base_int, count, label in regions:
    base = toAddr(base_int)
    print("=== vtable region %s ===" % label)
    for i in range(count):
        ea = base.add(i * 4)
        ptr = mem.getInt(ea) & 0xffffffff
        tgt = toAddr(ptr)
        fn = fm.getFunctionAt(tgt)
        name = fn.getName() if fn else "<no_function>"
        print("[%02d] %s -> %08x (%s)" % (i, ea, ptr, name))
    print("")
