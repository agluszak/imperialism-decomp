#@author codex
#@category Analysis

TARGET = bytes(bytearray([0xB6,0x03]))
mem = currentProgram.getMemory()

print('=== raw 0x03B6 hits ===')
for blk in mem.getBlocks():
    if not blk.isInitialized():
        continue
    start = blk.getStart()
    end = blk.getEnd()
    addr = start
    while True:
        found = mem.findBytes(addr, end, TARGET, None, True, monitor)
        if found is None:
            break
        print('%s | block=%s' % (found, blk.getName()))
        addr = found.add(1)
