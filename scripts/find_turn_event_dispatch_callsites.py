#@author codex
#@category Analysis

TARGETS = ['0x006a21bc', '0x006a1344']
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== potential DispatchGlobalTurnEventCode callsites ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins).lower()
    if ins.getMnemonicString().upper() == 'CALL' and '+ 0x4c]' in txt:
        prev = ins.getPrevious()
        window = []
        hit = False
        for _ in range(12):
            if prev is None:
                break
            ptxt = str(prev).lower()
            window.append((prev.getAddress(), str(prev)))
            if any(t in ptxt for t in TARGETS):
                hit = True
            prev = prev.getPrevious()
        if not hit:
            continue
        window.reverse()
        addr = ins.getAddress()
        fn = fm.getFunctionContaining(addr)
        fn_name = fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (addr, fn_name, ins))
        for a, t in window:
            print('  %s: %s' % (a, t))
        count += 1

print('TOTAL_MATCHES=%d' % count)
