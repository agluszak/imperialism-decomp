#@author codex
#@category Analysis

TARGETS = [
    0x00652A80,  # city production dialog controller vtable
    0x00647428,  # A1 template vtable (hotkey path)
    0x0064BAC0,  # D0 template vtable
]

mem = currentProgram.getMemory()
refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

for t in TARGETS:
    pat = bytearray([(t >> (8 * i)) & 0xff for i in range(4)])
    print("=== raw dword scan for 0x%08x ===" % t)
    hits = 0
    with_refs = 0
    for blk in mem.getBlocks():
        if not blk.isInitialized():
            continue
        start = blk.getStart()
        end = blk.getEnd()
        addr = start
        while True:
            found = mem.findBytes(addr, end, bytes(pat), None, True, monitor)
            if found is None:
                break
            hits += 1
            refs = list(refman.getReferencesTo(found))
            if refs:
                with_refs += 1
                print("  %s block=%s refs=%d" % (found, blk.getName(), len(refs)))
                for r in refs[:8]:
                    src = r.getFromAddress()
                    fn = fm.getFunctionContaining(src)
                    fn_name = fn.getName() if fn else "<no_function>"
                    print("    from %s type=%s fn=%s" % (src, r.getReferenceType(), fn_name))
                if len(refs) > 8:
                    print("    ... +%d more refs" % (len(refs) - 8))
            addr = found.add(1)
    print("  total_hits=%d with_refs=%d" % (hits, with_refs))
    print("")
