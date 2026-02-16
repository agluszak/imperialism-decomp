#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

TARGET_GLOBAL = '0x006a21bc'
re_call = re.compile(r'^\s*call\s+dword ptr \[([a-z]{2,3}) \+ 0x4c\]\s*$', re.IGNORECASE)
re_mov_abs = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[' + re.escape(TARGET_GLOBAL) + r'\]\s*$', re.IGNORECASE)
re_mov_deref = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[([a-z]{2,3})\]\s*$', re.IGNORECASE)
re_mov_reg = re.compile(r'^\s*mov\s+([a-z]{2,3}),([a-z]{2,3})\s*$', re.IGNORECASE)

CAT_PTR='ptr'
CAT_VT='vt'

print('=== precise g_pUiRuntimeContext CALL [vtable+0x4C] sites ===')
count=0

for ins in listing.getInstructions(True):
    m = re_call.match(str(ins).strip())
    if not m:
        continue
    vreg = m.group(1).lower()
    fn = fm.getFunctionContaining(ins.getAddress())
    if fn is None:
        continue

    # walk instructions in function up to call-site and propagate simple register provenance
    reg_cat = {}
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        h = it.next()
        t = str(h).strip().lower()

        ma = re_mov_abs.match(t)
        if ma:
            reg_cat[ma.group(1).lower()] = CAT_PTR
        else:
            md = re_mov_deref.match(t)
            if md:
                dst = md.group(1).lower()
                src = md.group(2).lower()
                if reg_cat.get(src) == CAT_PTR:
                    reg_cat[dst] = CAT_VT
                else:
                    reg_cat.pop(dst, None)
            else:
                mr = re_mov_reg.match(t)
                if mr:
                    dst = mr.group(1).lower()
                    src = mr.group(2).lower()
                    if src in reg_cat:
                        reg_cat[dst] = reg_cat[src]
                    else:
                        reg_cat.pop(dst, None)

        if h.getAddress() == ins.getAddress():
            break

    if reg_cat.get(vreg) != CAT_VT:
        continue

    pushes=[]
    p=ins.getPrevious()
    for _ in range(14):
        if p is None: break
        if p.getMnemonicString().upper()=='PUSH':
            pushes.append((p.getAddress(), str(p)))
        # stop at previous call to avoid crossing call boundary
        if p.getMnemonicString().upper()=='CALL':
            break
        p=p.getPrevious()

    arg0 = pushes[0][1] if len(pushes)>0 else '<none>'
    arg1 = pushes[1][1] if len(pushes)>1 else '<none>'
    print('%s | %s | arg0=%s | arg1=%s | %s' % (
        ins.getAddress(), fn.getName(), arg0, arg1, ins
    ))
    count += 1

print('TOTAL=%d' % count)
