#@author codex
#@category Analysis

listing = currentProgram.getListing()
addrs = [0x00402e7d,0x00403053,0x0040488b,0x00401f4b,0x004061db]
for a in addrs:
    addr = toAddr(a)
    ins = listing.getInstructionAt(addr)
    print('=== %s ===' % addr)
    if ins is None:
        print('No instruction')
        continue
    cur = ins
    for _ in range(4):
        p = cur.getPrevious()
        if p is None:
            break
        cur = p
    for _ in range(20):
        if cur is None:
            break
        print('%s: %s' % (cur.getAddress(), cur))
        cur = cur.getNext()
    print('')
