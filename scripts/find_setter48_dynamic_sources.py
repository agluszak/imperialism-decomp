#@author codex
#@category Analysis

import re
listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

re_call = re.compile(r'^\s*call\s+dword ptr \[[a-z]{2,3} \+ 0x48\]\s*$', re.IGNORECASE)

print('=== dynamic arg sources for CALL [*+0x48] where gctx is nearby ===')
for ins in listing.getInstructions(True):
    if not re_call.match(str(ins).strip()):
        continue
    prev=ins.getPrevious(); window=[]; marker=False; pushes=[]
    for _ in range(30):
        if prev is None: break
        t=str(prev)
        window.append((prev.getAddress(),t))
        if '0x006a21bc' in t.lower(): marker=True
        if prev.getMnemonicString().upper()=='PUSH': pushes.append((prev.getAddress(),t))
        prev=prev.getPrevious()
    if not marker or not pushes: continue
    arg=pushes[0][1]
    low=arg.lower().strip()
    if 'push 0x' in low or (low.startswith('push ') and low[5:].isdigit()):
        continue
    fn=fm.getFunctionContaining(ins.getAddress()); fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | arg=%s' % (ins.getAddress(), fnn, arg))
    for a,t in reversed(window[:12]):
        print('  %s: %s' % (a,t))
