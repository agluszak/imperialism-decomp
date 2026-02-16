#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== comparisons against 0x3B6 ===')
count = 0
for ins in listing.getInstructions(True):
    m = ins.getMnemonicString().upper()
    if m not in ('CMP','SUB','TEST'):
        continue
    txt = str(ins)
    low = txt.lower()
    if '0x3b6' in low or ', 950' in low or ',950' in low:
        fn = fm.getFunctionContaining(ins.getAddress())
        fnn = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (ins.getAddress(), fnn, txt))
        count += 1
print('TOTAL=%d' % count)
