#@author codex
#@category Analysis

import re

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

re_imm_push = re.compile(r'^\s*push\s+(0x[0-9a-f]+|\d+)\s*$', re.IGNORECASE)

print('=== dynamic callsites to g_dispatch_ctx vfunc +0x4C ===')
count = 0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue
    call_txt = str(ins).lower()
    if '+ 0x4c]' not in call_txt and '+0x4c]' not in call_txt:
        continue

    prev = ins.getPrevious()
    window = []
    pushes = []
    marker = False
    for _ in range(26):
        if prev is None:
            break
        ptxt = str(prev)
        low = ptxt.lower()
        window.append((prev.getAddress(), ptxt))
        if '0x006a21bc' in low:
            marker = True
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), ptxt))
        prev = prev.getPrevious()

    if not marker or not pushes:
        continue

    arg_push = pushes[0][1]
    if re_imm_push.match(arg_push.strip()):
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | arg=%s @ %s | %s' % (
        ins.getAddress(), fn_name, pushes[0][1], pushes[0][0], ins
    ))
    for a, t in reversed(window[:12]):
        print('  %s: %s' % (a, t))
    count += 1

print('TOTAL_DYNAMIC=%d' % count)
