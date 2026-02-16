#@author codex
#@category Analysis

from ghidra.util import NumericUtilities

listing = currentProgram.getListing()
refman = currentProgram.getReferenceManager()

TARGETS = [0x0048542a, 0x00485910, 0x00413d20, 0x00414720]
mem = currentProgram.getMemory()

for t in TARGETS:
    pat = bytearray([(t >> (8*i)) & 0xff for i in range(4)])
    print('=== raw dword scan for 0x%08x ===' % t)
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
                print('  %s block=%s refs=%d' % (found, blk.getName(), len(refs)))
            addr = found.add(1)
    print('  total_hits=%d with_refs=%d' % (hits, with_refs))
    print('')
