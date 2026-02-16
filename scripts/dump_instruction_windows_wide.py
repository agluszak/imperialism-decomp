#@author codex
#@category Analysis

listing = currentProgram.getListing()

TARGETS = [0x004a9a9c, 0x004bc0bf, 0x00511ed3, 0x0058e226]

for t in TARGETS:
    addr = toAddr(t)
    ins = listing.getInstructionAt(addr)
    if ins is None:
        ins = listing.getInstructionContaining(addr)
    print('=== WIDE WINDOW @ %s ===' % addr)
    if ins is None:
        print('No instruction at target')
        continue

    cur = ins
    for _ in range(35):
        p = cur.getPrevious()
        if p is None:
            break
        cur = p

    for _ in range(90):
        if cur is None:
            break
        print('%s: %s' % (cur.getAddress(), cur))
        cur = cur.getNext()
    print('')
