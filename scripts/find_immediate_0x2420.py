#@author codex
#@category Analysis
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.listing import CodeUnit

TARGET = 0x2420
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== immediate/use scan for 0x%X ===' % TARGET)
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins)
    if '0x%x' % TARGET in txt.lower() or ' %d' % TARGET in txt or ',%d' % TARGET in txt:
        addr = ins.getAddress()
        fn = fm.getFunctionContaining(addr)
        fn_name = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (addr, fn_name, txt))
        count += 1

print('TOTAL_MATCHES=%d' % count)
