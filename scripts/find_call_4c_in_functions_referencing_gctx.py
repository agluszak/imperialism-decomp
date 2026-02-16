#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
refman = currentProgram.getReferenceManager()

target = toAddr(0x006a21bc)
re_call_4c = re.compile(r'^\s*call\s+dword ptr \[[a-z]{2,3} \+ 0x4c\]\s*$', re.IGNORECASE)

funcs = {}
for r in refman.getReferencesTo(target):
    fn = fm.getFunctionContaining(r.getFromAddress())
    if fn:
        funcs[fn.getEntryPoint()] = fn

print('=== CALL [*+0x4C] inside functions that reference g_pUiRuntimeContext ===')
for ep in sorted(funcs.keys(), key=lambda a: a.getOffset()):
    fn = funcs[ep]
    hits = []
    for ins in listing.getInstructions(fn.getBody(), True):
        txt = str(ins).strip()
        if not re_call_4c.match(txt):
            continue
        prev = ins.getPrevious()
        pushes = []
        for _ in range(10):
            if prev is None:
                break
            ptxt = str(prev).strip()
            if ptxt.upper().startswith('PUSH '):
                pushes.append('%s: %s' % (prev.getAddress(), ptxt))
            prev = prev.getPrevious()
        hits.append((ins.getAddress(), txt, pushes[:3]))
    if hits:
        print('%s | %s | hits=%d' % (fn.getEntryPoint(), fn.getName(), len(hits)))
        for addr, txt, pushes in hits:
            p0 = pushes[0] if pushes else '<none>'
            print('  %s | %s | arg_hint=%s' % (addr, txt, p0))

print('=== done ===')
