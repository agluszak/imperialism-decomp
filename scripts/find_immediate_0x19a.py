#@author codex
#@category Analysis

TARGET = 0x19A
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== immediate/use scan for 0x%X ===' % TARGET)
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins)
    low = txt.lower()
    if ('0x%x' % TARGET) in low or (' %d' % TARGET) in txt or (',%d' % TARGET) in txt:
        addr = ins.getAddress()
        fn = fm.getFunctionContaining(addr)
        fn_name = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (addr, fn_name, txt))
        count += 1

print('TOTAL_MATCHES=%d' % count)
