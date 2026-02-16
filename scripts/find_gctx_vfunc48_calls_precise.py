#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

TARGET_GLOBAL = '0x006a21bc'
re_call = re.compile(r'^\s*call\s+dword ptr \[([a-z]{2,3}) \+ 0x48\]\s*$', re.IGNORECASE)
re_mov_abs = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[' + re.escape(TARGET_GLOBAL) + r'\]\s*$', re.IGNORECASE)
re_mov_deref = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[([a-z]{2,3})\]\s*$', re.IGNORECASE)
re_mov_reg = re.compile(r'^\s*mov\s+([a-z]{2,3}),([a-z]{2,3})\s*$', re.IGNORECASE)

CAT_PTR = 'ptr'
CAT_VT = 'vt'

print('=== precise g_pUiRuntimeContext CALL [vtable+0x48] sites ===')
count = 0
for ins in listing.getInstructions(True):
    m = re_call.match(str(ins).strip())
    if not m:
        continue
    vreg = m.group(1).lower()

    prev = ins.getPrevious()
    hist = []
    for _ in range(80):
        if prev is None:
            break
        hist.append(prev)
        prev = prev.getPrevious()
    hist.reverse()

    reg_cat = {}
    for h in hist:
        t = str(h).strip().lower()
        ma = re_mov_abs.match(t)
        if ma:
            reg_cat[ma.group(1).lower()] = CAT_PTR
            continue
        md = re_mov_deref.match(t)
        if md:
            dst = md.group(1).lower()
            src = md.group(2).lower()
            if reg_cat.get(src) == CAT_PTR:
                reg_cat[dst] = CAT_VT
            else:
                reg_cat.pop(dst, None)
            continue
        mr = re_mov_reg.match(t)
        if mr:
            dst = mr.group(1).lower()
            src = mr.group(2).lower()
            if src in reg_cat:
                reg_cat[dst] = reg_cat[src]
            else:
                reg_cat.pop(dst, None)
            continue

    if reg_cat.get(vreg) != CAT_VT:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fnn = fn.getName() if fn else '<no_function>'
    pushes=[]
    p=ins.getPrevious()
    for _ in range(14):
        if p is None:
            break
        if p.getMnemonicString().upper()=='PUSH':
            pushes.append((p.getAddress(), str(p)))
        p=p.getPrevious()

    arg = pushes[0][1] if pushes else '<none>'
    print('%s | %s | arg=%s | %s' % (ins.getAddress(), fnn, arg, ins))
    count += 1

print('TOTAL=%d' % count)
