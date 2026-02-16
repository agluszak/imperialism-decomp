#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

TARGET_GLOBAL = '0x006a21bc'
OFFSETS = [0x14, 0x18, 0x48, 0x4c]

re_call_mem = re.compile(r'^\s*call\s+dword ptr \[([a-z]{2,3}) \+ 0x([0-9a-f]+)\]\s*$', re.IGNORECASE)
re_mov_global = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[' + re.escape(TARGET_GLOBAL) + r'\]\s*$', re.IGNORECASE)
re_mov_deref = re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[([a-z]{2,3})\]\s*$', re.IGNORECASE)

print('=== g_pUiRuntimeContext virtual callsites by vtable offset ===')
print('target_global=%s offsets=%s' % (TARGET_GLOBAL, ','.join('0x%x' % o for o in OFFSETS)))

hits = 0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue

    txt = str(ins).strip()
    m = re_call_mem.match(txt)
    if not m:
        continue

    call_reg = m.group(1).lower()
    off = int(m.group(2), 16)
    if off not in OFFSETS:
        continue

    prev = ins.getPrevious()
    window = []
    gctx_regs = set()
    vtbl_regs = set()

    for _ in range(24):
        if prev is None:
            break
        ptxt = str(prev).strip()
        low = ptxt.lower()
        window.append((prev.getAddress(), ptxt))

        m1 = re_mov_global.match(low)
        if m1:
            gctx_regs.add(m1.group(1).lower())

        m2 = re_mov_deref.match(low)
        if m2:
            dst = m2.group(1).lower()
            src = m2.group(2).lower()
            if src in gctx_regs:
                vtbl_regs.add(dst)
            if src in vtbl_regs:
                vtbl_regs.add(dst)

        prev = prev.getPrevious()

    if call_reg not in vtbl_regs:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | CALL [vtable + 0x%x]' % (ins.getAddress(), fn_name, off))

    # show nearest pushes as arg hints
    shown = 0
    for a, t in window:
        if t.upper().startswith('PUSH '):
            print('  arg_hint %s: %s' % (a, t))
            shown += 1
            if shown >= 3:
                break

    for a, t in reversed(window[:10]):
        print('  %s: %s' % (a, t))

    hits += 1

print('TOTAL_HITS=%d' % hits)
