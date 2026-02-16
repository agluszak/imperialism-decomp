#@author codex
#@category Analysis
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

for start,end in [(0x0056af70,0x0056afc8),(0x0056b020,0x0056b080)]:
    print('=== WINDOW %08X..%08X ===' % (start,end))
    ins = listing.getInstructionAt(toAddr(start))
    if ins is None:
        ins = listing.getInstructionAfter(toAddr(start))
    while ins is not None and ins.getAddress().getOffset() <= end:
        fn = fm.getFunctionContaining(ins.getAddress())
        fnn = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
        ins = ins.getNext()
