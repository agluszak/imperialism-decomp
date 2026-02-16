#@author codex
#@category Analysis

listing=currentProgram.getListing()
TARGETS=[0x0056afa8,0x0056b04e,0x0057821a,0x00575782,0x0057a59f]
for t in TARGETS:
    addr=toAddr(t)
    ins=listing.getInstructionAt(addr)
    if ins is None:
        ins=listing.getInstructionContaining(addr)
    print('=== WINDOW @ %08x ===' % t)
    if ins is None:
        print('no instruction')
        continue
    cur=ins
    for _ in range(80):
        p=cur.getPrevious()
        if p is None: break
        cur=p
    for _ in range(180):
        if cur is None: break
        print('%s: %s' % (cur.getAddress(),cur))
        cur=cur.getNext()
    print('')
