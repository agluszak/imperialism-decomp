#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== CALL [*+0x48] immediate arg pushes referencing g_pUiRuntimeContext ===')
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CALL':
        continue
    if '+ 0x48]' not in str(ins).lower():
        continue

    prev = ins.getPrevious()
    window=[]
    marker=False
    pushes=[]
    for _ in range(24):
        if prev is None:
            break
        txt = str(prev)
        window.append((prev.getAddress(), txt))
        low=txt.lower()
        if '0x006a21bc' in low:
            marker=True
        if prev.getMnemonicString().upper()=='PUSH':
            pushes.append((prev.getAddress(), txt))
        prev=prev.getPrevious()

    if not marker or not pushes:
        continue
    arg = pushes[0][1].lower()
    if 'push 0x' not in arg and not (arg.startswith('push ') and arg[5:].isdigit()):
        continue
    fn=fm.getFunctionContaining(ins.getAddress())
    fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | arg=%s | %s' % (ins.getAddress(), fnn, pushes[0][1], ins))
