#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

print('=== explicit MOV word ptr [reg+0x4],* where reg from g_pUiRuntimeContext in 30-ins window ===')
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper()!='MOV':
        continue
    t=str(ins).lower()
    if '[eax + 0x4]' not in t and '[ecx + 0x4]' not in t and '[edx + 0x4]' not in t and '[esi + 0x4]' not in t and '[edi + 0x4]' not in t:
        continue
    prev=ins.getPrevious(); marker=False
    for _ in range(30):
        if prev is None: break
        if '0x006a21bc' in str(prev).lower(): marker=True; break
        prev=prev.getPrevious()
    if not marker: continue
    fn=fm.getFunctionContaining(ins.getAddress()); fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
print('=== done ===')
