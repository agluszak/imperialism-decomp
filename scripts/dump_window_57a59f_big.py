#@author codex
#@category Analysis
listing=currentProgram.getListing()
addr=toAddr(0x0057a59f)
ins=listing.getInstructionAt(addr)
if ins is None: ins=listing.getInstructionContaining(addr)
print('TARGET',addr,ins)
if ins:
    cur=ins
    for _ in range(260):
        p=cur.getPrevious()
        if p is None: break
        cur=p
    for _ in range(420):
        if cur is None: break
        print('%s: %s' % (cur.getAddress(), cur))
        cur=cur.getNext()
