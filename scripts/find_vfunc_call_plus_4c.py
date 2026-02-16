#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== call-site scan for CALL [* + 0x4c] ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins)
    low = txt.lower()
    if ins.getMnemonicString().upper() == 'CALL' and '+ 0x4c]' in low:
        addr = ins.getAddress()
        fn = fm.getFunctionContaining(addr)
        fn_name = fn.getName() if fn else '<no_function>'
        prev = ins.getPrevious()
        prev_lines = []
        for _ in range(4):
            if prev is None:
                break
            prev_lines.append('%s: %s' % (prev.getAddress(), prev))
            prev = prev.getPrevious()
        prev_lines.reverse()
        print('%s | %s | %s' % (addr, fn_name, txt))
        for line in prev_lines:
            print('  ' + line)
        count += 1

print('TOTAL_CALLS=%d' % count)
