#@author codex
#@category Analysis
listing=currentProgram.getListing()
addr=toAddr(0x00409903)
ins=listing.getInstructionAt(addr)
if ins is None:
    ins=listing.getInstructionContaining(addr)
print('TARGET',addr,'ins',ins)
if ins:
    cur=ins
    for _ in range(20):
        p=cur.getPrevious()
        if p is None: break
        cur=p
    for _ in range(40):
        if cur is None: break
        print('%s: %s' % (cur.getAddress(),cur))
        cur=cur.getNext()
