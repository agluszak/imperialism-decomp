#@author codex
#@category Analysis

addresses = [
    0x004017B7,
    0x004094F8,
]

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

print("=== create/resync PTR_LAB_0066F120 tail thunks ===")
for a in addresses:
    addr = toAddr(a)
    fn = fm.getFunctionContaining(addr)
    if fn is not None:
        print("existing: %s at %s" % (fn.getName(), addr))
        continue

    ins = listing.getInstructionAt(addr)
    if ins is None:
        print("no instruction at %s" % addr)
        continue

    createFunction(addr, None)
    fn2 = fm.getFunctionContaining(addr)
    if fn2 is not None:
        print("created: %s at %s" % (fn2.getName(), addr))
    else:
        print("failed: %s" % addr)
