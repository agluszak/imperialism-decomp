#@author codex
#@category Analysis

listing = currentProgram.getListing()

TARGETS = [0x004a9a9c, 0x004bc0bf, 0x00511ed3, 0x0058e226]

for t in TARGETS:
    addr = toAddr(t)
    ins = listing.getInstructionAt(addr)
    if ins is None:
        # try nearby
        ins = listing.getInstructionContaining(addr)
    print('=== WINDOW @ %s ===' % addr)
    if ins is None:
        print('No instruction at target')
        continue

    # go 12 instructions back
    cur = ins
    for _ in range(12):
        p = cur.getPrevious()
        if p is None:
            break
        cur = p

    # print 40 instructions forward
    for _ in range(40):
        if cur is None:
            break
        print('%s: %s' % (cur.getAddress(), cur))
        cur = cur.getNext()
    print('')
