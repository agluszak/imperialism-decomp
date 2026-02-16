#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

re_mem_write = re.compile(r'^\s*(\w+)\s+(?:word ptr |dword ptr |byte ptr |qword ptr )?\[([a-z]{2,3}) \+ 0x4\],', re.IGNORECASE)
re_load_gctx = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[0x006a21bc\]\s*$', re.IGNORECASE)
re_deref_load = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[([a-z]{2,3})\]\s*$', re.IGNORECASE)


def norm(s):
    return s.strip().lower()


print('=== precise candidates: writes to [g_dispatch_ctx + 0x4] ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins)
    m = re_mem_write.match(txt)
    if not m:
        continue
    mnem = m.group(1).lower()
    if mnem not in ('mov', 'add', 'sub', 'or', 'and', 'xor', 'inc', 'dec'):
        continue

    base = m.group(2).lower()
    prev = ins.getPrevious()
    window = []
    gctx_regs = set()
    obj_regs = set()

    for _ in range(14):
        if prev is None:
            break
        ptxt = norm(str(prev))
        window.append((prev.getAddress(), str(prev)))

        m1 = re_load_gctx.match(ptxt)
        if m1:
            gctx_regs.add(m1.group(1).lower())

        m2 = re_deref_load.match(ptxt)
        if m2:
            dst = m2.group(1).lower()
            src = m2.group(2).lower()
            if src in gctx_regs or src in obj_regs:
                obj_regs.add(dst)

        prev = prev.getPrevious()

    if base not in gctx_regs and base not in obj_regs:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, txt))
    print('  base_reg=%s gctx_regs=%s obj_regs=%s' % (base, sorted(gctx_regs), sorted(obj_regs)))
    for a, t in reversed(window[:10]):
        print('  %s: %s' % (a, t))
    count += 1

print('TOTAL=%d' % count)
