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
re_jmp = re.compile(r'^\s*jmp\s+0x([0-9a-f]+)\s*$', re.IGNORECASE)


def resolve_target(fn):
    if fn is None:
        return None
    ins = listing.getInstructionAt(fn.getEntryPoint())
    if ins is None:
        return fn
    txt = str(ins).strip()
    m = re_jmp.match(txt)
    if not m:
        return fn
    try:
        tgt = toAddr(int(m.group(1), 16))
    except:
        return fn
    tgt_fn = fm.getFunctionContaining(tgt)
    return tgt_fn if tgt_fn is not None else fn


seen = set()
resolved = []
for i in range(entries):
    a = vtable.add(i * ptr_size)
    try:
        val = mem.getInt(a) & 0xffffffff
    except:
        continue
    if val < 0x00400000 or val > 0x00700000:
        continue
    fn = fm.getFunctionContaining(toAddr(val))
    fn = resolve_target(fn)
    if fn is None:
        continue
    key = fn.getEntryPoint().getOffset()
    if key in seen:
        continue
    seen.add(key)
    resolved.append((i * ptr_size, fn))

print('=== resolved vtable 0x0066f120 writer scan (+0x4 stores) ===')
for off, fn in resolved:
    lines = []
    for ins in listing.getInstructions(fn.getBody(), True):
        txt = str(ins)
        if re_write.match(txt):
            lines.append('%s: %s' % (ins.getAddress(), txt))
    if lines:
        print('+0x%X -> %s @ %s' % (off, fn.getName(), fn.getEntryPoint()))
        for l in lines[:20]:
            print('  ' + l)

print('=== done ===')
