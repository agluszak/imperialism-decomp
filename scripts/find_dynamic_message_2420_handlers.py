#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

re_cmp = re.compile(r'^\s*cmp\s+[^,]+,\s*0x2420\s*$', re.IGNORECASE)

print('=== message-handler style CMP *,0x2420 sites ===')
count = 0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CMP':
        continue
    txt = str(ins).strip()
    if not re_cmp.match(txt):
        continue
    fn = fm.getFunctionContaining(ins.getAddress())
    fnn = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, txt))
    count += 1
print('TOTAL=%d' % count)
