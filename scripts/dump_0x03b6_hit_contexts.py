#@author codex
#@category Analysis

listing=currentProgram.getListing()
hits=[0x0041464a,0x004357eb,0x004358ee,0x004995e7,0x00499baa,0x00499bf3,0x0049ccc8,0x0049ce9d,0x00618a4c,0x0067ef0c,0x0069c968]

for h in hits:
    addr=toAddr(h)
    print('=== context around %s ===' % addr)
    ins=listing.getInstructionContaining(addr)
    if ins is None:
        # dump bytes if no instruction
        b=[]
        mem=currentProgram.getMemory()
        for i in range(-8,9):
            a=addr.add(i)
            try:
                b.append('%02x' % (mem.getByte(a) & 0xff))
            except:
                b.append('??')
        print('  no instruction; bytes:', ' '.join(b))
        continue
    cur=ins
    for _ in range(4):
        p=cur.getPrevious()
        if p is None:
            break
        cur=p
    for _ in range(10):
        if cur is None:
            break
        print('  %s: %s' % (cur.getAddress(), cur))
        cur=cur.getNext()
    print('')
