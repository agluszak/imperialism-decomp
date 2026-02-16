#@author codex
#@category Analysis

import re

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()
re_call=re.compile(r'^\s*call\s+dword ptr \[([a-z]{2,3}) \+ 0x4c\]\s*$', re.IGNORECASE)
re_mov_abs=re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[0x006a21bc\]\s*$', re.IGNORECASE)
re_mov_deref=re.compile(r'^\s*mov\s+([a-z]{2,3}),dword ptr \[([a-z]{2,3})\]\s*$', re.IGNORECASE)

print('=== precise gctx +0x4c dynamic push sites (updated) ===')
for ins in listing.getInstructions(True):
    m=re_call.match(str(ins).strip())
    if not m: continue
    vr=m.group(1).lower()
    prev=ins.getPrevious(); win=[]
    for _ in range(20):
        if prev is None: break
        win.append(prev)
        prev=prev.getPrevious()
    gptr=set(); gvt=set()
    for h in reversed(win):
        t=str(h).strip().lower()
        ma=re_mov_abs.match(t)
        if ma: gptr.add(ma.group(1).lower()); continue
        md=re_mov_deref.match(t)
        if md:
            dst=md.group(1).lower(); src=md.group(2).lower()
            if src in gptr: gvt.add(dst)
            elif src in gvt: gvt.add(dst)
    if vr not in gvt: continue
    # nearest push
    p=ins.getPrevious(); arg='<none>'
    for _ in range(8):
        if p is None: break
        if p.getMnemonicString().upper()=='PUSH': arg=str(p); break
        p=p.getPrevious()
    fn=fm.getFunctionContaining(ins.getAddress()); fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | arg=%s' % (ins.getAddress(), fnn, arg))
print('=== done ===')
