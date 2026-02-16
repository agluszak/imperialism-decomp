#@author codex
#@category Analysis

listing=currentProgram.getListing()
start=toAddr(0x004853d0)
ins=listing.getInstructionAt(start)
if ins is None:
    ins=listing.getInstructionContaining(start)
for _ in range(80):
    if ins is None:
        break
    print('%s: %s' % (ins.getAddress(), ins))
    ins=ins.getNext()
