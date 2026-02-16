#@author codex
#@category Analysis

mem = currentProgram.getMemory()
rm = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

targets = [
    0x00000BC7,  # city production OK command id
    0x6F6B6179,  # 'okay'
    0x636E636C,  # 'cncl'
]

for t in targets:
    pat = bytes([(t >> (8 * i)) & 0xff for i in range(4)])
    print("=== raw dword scan for 0x%08x ===" % (t & 0xffffffff))
    total_hits = 0
    with_refs = 0
    for blk in mem.getBlocks():
        if not blk.isExecute():
            continue
        if not blk.isInitialized():
            continue
        start = blk.getStart()
        end = blk.getEnd()
        addr = start
        while True:
            found = mem.findBytes(addr, end, pat, None, True, monitor)
            if found is None:
                break
            total_hits += 1
            refs = list(rm.getReferencesTo(found))
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
    print("  total_hits=%d with_refs=%d" % (total_hits, with_refs))
    print("")
