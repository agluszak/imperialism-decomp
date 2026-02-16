#@author codex
#@category Analysis

mem=currentProgram.getMemory(); listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager(); refman=currentProgram.getReferenceManager()

# scan data for sequences containing 0x03b6 as 16-bit values
pat=bytes(bytearray([0xb6,0x03]))
print('=== potential word-table contexts around 0x03B6 bytes ===')
for blk in mem.getBlocks():
    if blk.getName() not in ['.data','.rdata','.text'] or not blk.isInitialized():
        continue
    addr=blk.getStart(); end=blk.getEnd()
    while True:
        hit=mem.findBytes(addr,end,pat,None,True,monitor)
        if hit is None: break
        # dump +/- 8 bytes
        start=hit.add(-8)
        b=bytearray(24)
        try:
            mem.getBytes(start,b)
            hx=' '.join('%02x'%x for x in b)
        except:
            hx='<read_fail>'
        fn=fm.getFunctionContaining(hit)
        fnn=fn.getName() if fn else '<no_function>'
        refs=list(refman.getReferencesTo(hit))
        print('%s | %s | fn=%s | refs=%d | bytes=%s' % (hit, blk.getName(), fnn, len(refs), hx))
        addr=hit.add(1)
print('=== done ===')
