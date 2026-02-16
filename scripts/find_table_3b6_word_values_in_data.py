#@author codex
#@category Analysis

listing=currentProgram.getListing()
mem=currentProgram.getMemory()
refman=currentProgram.getReferenceManager()

print('=== defined words == 0x03B6 in writable data blocks ===')
for blk in mem.getBlocks():
    name=blk.getName()
    if name not in ['.data','.rdata','.rsrc']:
        continue
    if not blk.isInitialized():
        continue
    addr=blk.getStart()
    end=blk.getEnd()
    while addr.compareTo(end) <= 0:
        d=listing.getDefinedDataAt(addr)
        if d and d.getLength()==2:
            val = d.getValue()
            try:
                v = int(str(val),0)
            except:
                v = None
            if v == 0x3b6:
                refs=list(refman.getReferencesTo(addr))
                print('%s | %s | refs=%d' % (addr,name,len(refs)))
        addr=addr.add(1)
print('=== done ===')
