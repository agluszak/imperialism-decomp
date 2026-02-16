#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

marker = '0x006a21bc'

print('=== dynamic g_pUiRuntimeContext->SetCurrentEventCode (+0x48) callsites ===')
count = 0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue
    txt = str(ins).lower()
    if '+ 0x48]' not in txt:
        continue

    prev = ins.getPrevious()
    window = []
    pushes = []
    marker_hit = False
    for _ in range(30):
        if prev is None:
            break
        ptxt = str(prev)
        low = ptxt.lower()
        window.append((prev.getAddress(), ptxt, prev.getMnemonicString().upper()))
        if marker in low:
            marker_hit = True
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), ptxt))
        prev = prev.getPrevious()

    if not marker_hit:
        continue
    if not pushes:
        continue

    code_push_addr, code_push_txt = pushes[0]
    low = code_push_txt.lower().strip()
    # immediate-ish forms: push 0x..., push 1234
    is_imm = ('push 0x' in low) or (low.startswith('push ') and low[5:].isdigit())
    if is_imm:
        continue

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, ins))
    print('  code_push: %s: %s' % (code_push_addr, code_push_txt))
    if len(pushes) > 1:
        print('  prev_push: %s: %s' % (pushes[1][0], pushes[1][1]))
    for a, t, _m in reversed(window[:12]):
        print('    %s: %s' % (a, t))
    count += 1

print('TOTAL_DYNAMIC_SETTER_SITES=%d' % count)
