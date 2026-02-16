#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

TARGET = '0x006a21bc'

re_mov_abs = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[' + re.escape(TARGET) + r'\]\s*$', re.IGNORECASE)
re_mov_deref = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[([a-z]{2,3})\]\s*$', re.IGNORECASE)
re_mov_reg = re.compile(r'^\s*mov\s+([a-z]{2,3}),([a-z]{2,3})\s*$', re.IGNORECASE)
re_write_plus4 = re.compile(r'^\s*(mov|add|sub|or|and|xor|inc|dec)\s+(?:word ptr |dword ptr |byte ptr )?\[([a-z]{2,3}) \+ 0x4\],', re.IGNORECASE)

CAT_PTR = 'ptr'
CAT_OBJ = 'obj'

print('=== writes to [g_pUiRuntimeContext + 0x4] via resolved register tracking ===')
count = 0

for fn in fm.getFunctions(True):
    reg_cat = {}
    for ins in listing.getInstructions(fn.getBody(), True):
        t = str(ins).strip().lower()

        m = re_mov_abs.match(t)
        if m:
            reg_cat[m.group(1).lower()] = CAT_PTR
            continue

        m = re_mov_deref.match(t)
        if m:
            dst = m.group(1).lower()
            src = m.group(2).lower()
            if reg_cat.get(src) == CAT_PTR:
                reg_cat[dst] = CAT_OBJ
            else:
                reg_cat.pop(dst, None)
            continue

        m = re_mov_reg.match(t)
        if m:
            dst = m.group(1).lower()
            src = m.group(2).lower()
            if src in reg_cat:
                reg_cat[dst] = reg_cat[src]
            else:
                reg_cat.pop(dst, None)
            continue

        m = re_write_plus4.match(t)
        if m:
            base = m.group(2).lower()
            if reg_cat.get(base) == CAT_OBJ:
                print('%s | %s | %s' % (ins.getAddress(), fn.getName(), ins))
                count += 1

print('TOTAL=%d' % count)
