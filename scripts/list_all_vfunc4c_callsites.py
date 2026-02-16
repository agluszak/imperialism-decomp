#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== all CALL [* +0x4C] sites ===')
count = 0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue
    txt = str(ins)
    low = txt.lower()
    if '+ 0x4c]' not in low:
        continue

    prev = ins.getPrevious()
    pushes = []
    window = []
    marker = False
    for _ in range(18):
        if prev is None:
            break
        ptxt = str(prev)
        window.append((prev.getAddress(), ptxt))
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), ptxt))
        if '0x006a21bc' in ptxt.lower():
            marker = True
        prev = prev.getPrevious()

    fn = fm.getFunctionContaining(ins.getAddress())
    fn_name = fn.getName() if fn else '<no_function>'

    code_push = pushes[0][1] if pushes else '<none>'
    code_push_addr = pushes[0][0] if pushes else None
    extra_push = pushes[1][1] if len(pushes) > 1 else '<none>'
    print('%s | %s | marker=%s | code=%s @ %s | extra=%s | %s' % (
        ins.getAddress(), fn_name, marker, code_push, code_push_addr, extra_push, txt
    ))
    count += 1

print('TOTAL=%d' % count)
