#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

re_w = re.compile(r'^\s*(mov|add|sub|or|and|xor|inc|dec)\s+(?:word ptr |dword ptr |byte ptr |qword ptr )?\[([a-z]{2,3}) \+ 0x60\],', re.IGNORECASE)

print('=== writes to [reg + 0x60] across program ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins)
    if not re_w.match(txt):
        continue
    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, txt))
    count += 1

print('TOTAL=%d' % count)
