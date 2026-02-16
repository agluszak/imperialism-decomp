#@author codex
#@category Analysis

TARGET = [0xB6, 0x03]
mem = currentProgram.getMemory()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== raw hits for 0x03B6 ===')
for blk in mem.getBlocks():
    if not blk.isInitialized():
        continue
    start = blk.getStart()
    end = blk.getEnd()
    addr = start
    while True:
        found = mem.findBytes(addr, end, bytes(bytearray(TARGET)), None, True, monitor)
        if found is None:
            break
        cu = listing.getCodeUnitContaining(found)
        fn = fm.getFunctionContaining(found)
        fn_name = fn.getName() if fn else '<no_func>'
        cu_txt = str(cu) if cu else '<no_codeunit>'
        print('%s | block=%s | fn=%s | cu=%s' % (found, blk.getName(), fn_name, cu_txt))
        addr = found.add(1)
print('=== done ===')
