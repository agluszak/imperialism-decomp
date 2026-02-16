#@author codex
#@category Analysis

from ghidra.program.model.address import Address

TARGET = [0xB6, 0x03]  # little-endian 0x03B6
mem = currentProgram.getMemory()
refman = currentProgram.getReferenceManager()
blocks = mem.getBlocks()

print('=== raw byte scan for 0x03B6 with xrefs ===')
print('pattern bytes:', TARGET)

total_hits = 0
xref_hits = 0
for blk in blocks:
    if not blk.isInitialized():
        continue
    start = blk.getStart()
    end = blk.getEnd()
    addr = start
    while addr is not None and addr.compareTo(end) <= 0:
        found = mem.findBytes(addr, end, bytes(bytearray(TARGET)), None, True, monitor)
        if found is None:
            break
        total_hits += 1
        refs = list(refman.getReferencesTo(found))
        if refs:
            xref_hits += 1
            print('%s | block=%s | refs=%d' % (found, blk.getName(), len(refs)))
            for r in refs[:8]:
                print('  from %s type=%s' % (r.getFromAddress(), r.getReferenceType()))
            if len(refs) > 8:
                print('  ... +%d more refs' % (len(refs) - 8))
        addr = found.add(1)

print('TOTAL_RAW_HITS=%d' % total_hits)
print('HITS_WITH_XREFS=%d' % xref_hits)
