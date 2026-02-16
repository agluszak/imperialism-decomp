#@author codex
#@category Analysis

mem = currentProgram.getMemory()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

pat = bytes(bytearray([0xB6,0x03]))
print('=== raw 0x03B6 hits with nearby disassembly ===')
for blk in mem.getBlocks():
    if not blk.isInitialized():
        continue
    addr = blk.getStart()
    end = blk.getEnd()
    while True:
        hit = mem.findBytes(addr, end, pat, None, True, monitor)
        if hit is None:
            break
        fn = fm.getFunctionContaining(hit)
        fnn = fn.getName() if fn else '<no_function>'
        print('%s | block=%s | fn=%s' % (hit, blk.getName(), fnn))
        ins = listing.getInstructionAt(hit)
        if ins:
            print('  ins=%s' % ins)
        addr = hit.add(1)
print('=== done ===')
