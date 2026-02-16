#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

re_call = re.compile(r'^\s*call\s+dword ptr \[([a-z]{2,3}) \+ 0x4c\]\s*$', re.IGNORECASE)
re_mov_abs = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[0x006a21bc\]\s*$', re.IGNORECASE)
re_mov_deref = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[([a-z]{2,3})\]\s*$', re.IGNORECASE)
re_mov_reg = re.compile(r'^\s*mov\s+([a-z]{2,3}),([a-z]{2,3})\s*$', re.IGNORECASE)

CAT_GCTX_PTR = 'gctx_ptr'
CAT_GCTX_VT = 'gctx_vtable'

def low(s):
    return s.strip().lower()

print('=== precise g_dispatch_ctx CALL [vtable+0x4c] sites ===')
count = 0
for ins in listing.getInstructions(True):
    mcall = re_call.match(str(ins))
    if not mcall:
        continue
    vtbl_reg = mcall.group(1).lower()

    # Collect a larger linear window before call
    prev = ins.getPrevious()
    hist = []
    for _ in range(90):
        if prev is None:
            break
        hist.append(prev)
        prev = prev.getPrevious()
    hist.reverse()

    reg_cat = {}  # reg -> category
    for h in hist:
        t = low(str(h))

        m = re_mov_abs.match(t)
        if m:
            reg_cat[m.group(1).lower()] = CAT_GCTX_PTR
            continue

        m = re_mov_deref.match(t)
        if m:
            dst = m.group(1).lower()
            src = m.group(2).lower()
            src_cat = reg_cat.get(src)
            if src_cat == CAT_GCTX_PTR:
                reg_cat[dst] = CAT_GCTX_VT
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

        # conservative kill on writes to general regs
        if t.startswith('mov '):
            left = t[4:].split(',', 1)[0].strip()
            if left in ('eax','ebx','ecx','edx','esi','edi','ebp'):
                if left not in ():
                    # keep if exact pattern handlers above already handled
                    if not re_mov_abs.match(t) and not re_mov_deref.match(t) and not re_mov_reg.match(t):
                        reg_cat.pop(left, None)

    if reg_cat.get(vtbl_reg) != CAT_GCTX_VT:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'

    # nearest pushes
    pushes = []
    prev = ins.getPrevious()
    for _ in range(20):
        if prev is None:
            break
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), str(prev)))
        prev = prev.getPrevious()

    arg = pushes[0][1] if pushes else '<none>'
    arg_addr = pushes[0][0] if pushes else None
    print('%s | %s | arg=%s @ %s | %s' % (
        ins.getAddress(), fn_name, arg, arg_addr, ins
    ))
    count += 1

print('TOTAL=%d' % count)
