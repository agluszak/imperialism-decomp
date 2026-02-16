#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

print('=== CALL [*+0x4C] with non-immediate arg and nearby ADD/SUB on arg register ===')
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper()!='CALL': continue
    if '+ 0x4c]' not in str(ins).lower(): continue
    prev=ins.getPrevious(); pushes=[]; window=[]
    for _ in range(20):
        if prev is None: break
        t=str(prev); window.append((prev.getAddress(),t))
        if prev.getMnemonicString().upper()=='PUSH': pushes.append((prev.getAddress(),t))
        prev=prev.getPrevious()
    if not pushes: continue
    arg = pushes[0][1].strip()
    low = arg.lower()
    if 'push 0x' in low or (low.startswith('push ') and low[5:].isdigit()):
        continue
    reg = low.replace('push','').strip()
    if reg not in ['eax','ebx','ecx','edx','esi','edi','ebp']:
        continue
    math=False
    for _a,t in window:
        tl=t.lower()
        if tl.startswith('add '+reg+',') or tl.startswith('sub '+reg+',') or tl.startswith('imul '+reg+','):
            math=True; break
    if not math: continue
    fn=fm.getFunctionContaining(ins.getAddress()); fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | arg=%s' % (ins.getAddress(), fnn, arg))
print('=== done ===')
