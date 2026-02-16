#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== CALL [*+0x4C] with nearby PUSH 0x3B6 ===')
hits = 0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue
    txt = str(ins).lower()
    if '+ 0x4c]' not in txt:
        continue

    prev = ins.getPrevious()
    found = False
    window = []
    for _ in range(20):
        if prev is None:
            break
        ptxt = str(prev)
        window.append((prev.getAddress(), ptxt))
        low = ptxt.lower()
        if 'push 0x3b6' in low or 'push 950' in low:
            found = True
        prev = prev.getPrevious()

    if not found:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, ins))
    for a,t in reversed(window[:10]):
        print('  %s: %s' % (a,t))
    hits += 1

print('TOTAL=%d' % hits)
