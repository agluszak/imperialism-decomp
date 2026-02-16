#@author codex
#@category Analysis

TARGET = '0x3b6'
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== CALL [*+0x4c] with nearby 0x3B6 immediate ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins).lower()
    if ins.getMnemonicString().upper() == 'CALL' and '+ 0x4c]' in txt:
        # collect previous 8 instructions
        prev = ins.getPrevious()
        lines = []
        hit = False
        for _ in range(8):
            if prev is None:
                break
            ptxt = str(prev)
            if TARGET in ptxt.lower():
                hit = True
            lines.append('%s: %s' % (prev.getAddress(), ptxt))
            prev = prev.getPrevious()
        if hit:
            lines.reverse()
            addr = ins.getAddress()
            fn = fm.getFunctionContaining(addr)
            fn_name = fn.getName() if fn else '<no_function>'
            print('%s | %s | %s' % (addr, fn_name, ins))
            for line in lines:
                print('  ' + line)
            count += 1

print('TOTAL_MATCHES=%d' % count)
