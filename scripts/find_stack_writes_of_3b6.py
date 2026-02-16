#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

# find stores of immediate 0x3B6 to stack locals
re_store = re.compile(r'^\s*mov\s+(?:word ptr |dword ptr )?\[esp \+ [^\]]+\],\s*0x3b6\s*$', re.IGNORECASE)

print('=== stack stores of immediate 0x3B6 ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins).strip()
    if not re_store.match(txt):
        continue
    fn = fm.getFunctionContaining(ins.getAddress())
    fnn = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, txt))
    count += 1
print('TOTAL=%d' % count)
