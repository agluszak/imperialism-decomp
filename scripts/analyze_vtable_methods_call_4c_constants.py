#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()

vtable = toAddr(0x0066f120)
ptr_size = currentProgram.getDefaultPointerSize()
entries = 80

re_jmp = re.compile(r'^\s*jmp\s+0x([0-9a-f]+)\s*$', re.IGNORECASE)
re_call_4c = re.compile(r'^\s*call\s+dword ptr \[[a-z]{2,3} \+ 0x4c\]\s*$', re.IGNORECASE)
re_push_imm = re.compile(r'^\s*push\s+(0x[0-9a-f]+|\d+)\s*$', re.IGNORECASE)


def resolve_target(fn):
    if fn is None:
        return None
    ins = listing.getInstructionAt(fn.getEntryPoint())
    if ins is None:
        return fn
    m = re_jmp.match(str(ins).strip())
    if not m:
        return fn
    try:
        tgt = toAddr(int(m.group(1), 16))
    except:
        return fn
    tgt_fn = fm.getFunctionContaining(tgt)
    return tgt_fn if tgt_fn else fn


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

print('=== resolved vtable methods: internal +0x4C dispatch constants ===')
for off, fn in resolved:
    found = False
    for ins in listing.getInstructions(fn.getBody(), True):
        txt = str(ins).strip()
        if not re_call_4c.match(txt):
            continue
        prev = ins.getPrevious()
        imm = None
        for _ in range(8):
            if prev is None:
                break
            ptxt = str(prev).strip()
            m = re_push_imm.match(ptxt)
            if m:
                imm = m.group(1)
                break
            prev = prev.getPrevious()
        if not found:
            print('+0x%X -> %s @ %s' % (off, fn.getName(), fn.getEntryPoint()))
            found = True
        print('  %s: %s | nearest_imm=%s' % (ins.getAddress(), txt, imm))

print('=== done ===')
