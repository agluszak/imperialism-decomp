#@author codex
#@category Analysis

from ghidra.program.model.address import Address

addresses = [0x004064dd, 0x0040724d, 0x00408832, 0x00500200, 0x00500220]

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

print('=== create/resync residual stub functions ===')
for a in addresses:
    addr = toAddr(a)
    fn = fm.getFunctionContaining(addr)
    if fn:
        print('existing: %s at %s' % (fn.getName(), addr))
        continue
    dis = listing.getInstructionAt(addr)
    if dis is None:
        dis = listing.getInstructionAfter(addr.subtract(1))
        if dis is None or dis.getAddress() != addr:
            print('no instruction at %s' % addr)
            continue
    created = createFunction(addr, None)
    fn2 = fm.getFunctionContaining(addr)
    if fn2:
        print('created: %s at %s' % (fn2.getName(), addr))
    else:
        print('failed at %s created=%s' % (addr, str(created)))
