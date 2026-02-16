#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()

vtable = toAddr(0x0066f120)
ptr_size = currentProgram.getDefaultPointerSize()
entries = 80

re_write = re.compile(r'^\s*(mov|add|sub|or|and|xor|inc|dec)\s+(?:word ptr |dword ptr |byte ptr )?\[([a-z]{2,3}) \+ 0x4\],', re.IGNORECASE)

targets = []
seen = set()
for i in range(entries):
    a = vtable.add(i * ptr_size)
    try:
        val = mem.getInt(a) & 0xffffffff
    except:
        continue
    if val < 0x00400000 or val > 0x00700000:
        continue
    if val in seen:
        continue
    seen.add(val)
    fn = fm.getFunctionContaining(toAddr(val))
    if fn is None:
        continue
    targets.append(fn)

print('=== vtable 0x0066f120 state-slot writer scan (+0x4 stores) ===')
for fn in targets:
    body = fn.getBody()
    ins_iter = listing.getInstructions(body, True)
    lines = []
    for ins in ins_iter:
        txt = str(ins)
        if re_write.match(txt):
            lines.append('%s: %s' % (ins.getAddress(), txt))
    if lines:
        print('%s | %s' % (fn.getEntryPoint(), fn.getName()))
        for l in lines[:20]:
            print('  ' + l)

print('=== done ===')
