#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== CALL [* +0x48] sites with arg 0x3B6 or nearby ===')
hits = 0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue
    low = str(ins).lower()
    if '+ 0x48]' not in low and '+0x48]' not in low:
        continue

    prev = ins.getPrevious()
    window = []
    pushes = []
    for _ in range(16):
        if prev is None:
            break
        txt = str(prev)
        window.append((prev.getAddress(), txt))
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), txt))
        prev = prev.getPrevious()

    # setter usually takes: PUSH stateCode ; PUSH <flag/arg> ; CALL [vtable+0x48]
    # pushes[0] is nearest push to call-site.
    state_push = pushes[0][1].lower() if pushes else ''
    state_is_3b6 = ('push 0x3b6' in state_push) or ('push 950' in state_push)

    near_3b6 = False
    for _addr, txt in window:
        t = txt.lower()
        if '0x3b6' in t or '950' in t:
            near_3b6 = True
            break

    if not state_is_3b6 and not near_3b6:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, ins))
    if pushes:
        print('  arg_push=%s @ %s' % (pushes[0][1], pushes[0][0]))
    for a, t in reversed(window[:10]):
        print('  %s: %s' % (a, t))
    hits += 1

print('TOTAL=%d' % hits)
