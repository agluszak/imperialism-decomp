#@author codex
#@category Analysis

mem = currentProgram.getMemory()
refman = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

TARGETS = [
    0x004CE480, # CreateBuildingExpansionView
    0x004CECE0, # CreateArmoryView
    0x004D04B0, # CreateEngineerDialog
]

for t in TARGETS:
    pat = bytearray([(t >> (8*i)) & 0xff for i in range(4)])
    print('=== raw dword scan for 0x%08x ===' % t)
    hits = 0
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
            cfn = fm.getFunctionContaining(found)
            cfn_name = cfn.getName() if cfn else '<no_function>'
            d = listing.getDataContaining(found)
            dstr = d.toString() if d else '<no_data>'
            print('  hit %s block=%s refs=%d fn=%s data=%s' % (
                found, blk.getName(), len(refs), cfn_name, dstr
            ))
            addr = found.add(1)
    print('  total_hits=%d' % hits)
    print('')
