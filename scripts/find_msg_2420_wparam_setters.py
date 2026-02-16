#@author codex
#@category Analysis

import re
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

# heuristic: push something ; push 0x2420 ; call PostMessageA/SendMessageA
print('=== potential custom message 0x2420 send sites ===')
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue
    txt = str(ins)
    low = txt.lower()
    if 'postmessage' not in low and 'sendmessage' not in low and '0x006ab5' not in low:
        continue
    prev = ins.getPrevious()
    window=[]
    found=False
    for _ in range(20):
        if prev is None:
            break
        t=str(prev)
        window.append((prev.getAddress(), t))
        if 'push 0x2420' in t.lower() or 'push 9248' in t.lower():
            found=True
        prev = prev.getPrevious()
    if not found:
        continue
    fn = fm.getFunctionContaining(ins.getAddress())
    fnn = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
    for a,t in reversed(window[:10]):
        print('  %s: %s' % (a,t))
print('=== done ===')
