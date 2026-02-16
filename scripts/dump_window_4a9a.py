#@author codex
#@category Analysis

listing = currentProgram.getListing()
addr = toAddr(0x004a9a3e)
ins = listing.getInstructionAt(addr)
if ins is None:
    ins = listing.getInstructionContaining(addr)
print('TARGET', addr)
if ins is None:
    print('No instruction at target')
else:
    cur = ins
    for _ in range(140):
        p = cur.getPrevious()
        if p is None:
            break
        cur = p
    for _ in range(280):
        if cur is None:
            break
        print('%s: %s' % (cur.getAddress(), cur))
        cur = cur.getNext()
