#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

globals_markers = ['0x006a21bc', '0x006a1344']

print('=== dynamic event-code dispatch callsites (vfunc +0x4c) ===')
count = 0
for ins in listing.getInstructions(True):
    txt = str(ins).lower()
    if not (ins.getMnemonicString().upper() == 'CALL' and '+ 0x4c]' in txt):
        continue

    # gather previous instructions window
    prev = ins.getPrevious()
    window = []
    marker_hit = False
    pushes = []
    for _ in range(25):
        if prev is None:
            break
        ptxt = str(prev)
        low = ptxt.lower()
        window.append((prev.getAddress(), ptxt))
        if any(m in low for m in globals_markers):
            marker_hit = True
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), ptxt))
        prev = prev.getPrevious()

    if not marker_hit:
        continue
    if not pushes:
        continue

    # closest push before call is likely event code argument
    code_push_addr, code_push_txt = pushes[0]
    low = code_push_txt.lower()
    is_immediate = ('0x' in low) or low.strip().endswith(tuple(str(i) for i in range(10)))
    if is_immediate:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, ins))
    print('  code_push: %s: %s' % (code_push_addr, code_push_txt))
    if len(pushes) > 1:
        print('  prev_push: %s: %s' % (pushes[1][0], pushes[1][1]))
    # show last 10 lines before call
    for a, t in reversed(window[:10]):
        print('    %s: %s' % (a, t))
    count += 1

print('TOTAL_DYNAMIC_SITES=%d' % count)
