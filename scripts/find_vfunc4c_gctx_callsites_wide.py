#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== +0x4c calls with g_pUiRuntimeContext marker in previous 80 ins ===')
count=0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper()!='CALL':
        continue
    low=str(ins).lower()
    if '+ 0x4c]' not in low:
        continue
    prev=ins.getPrevious()
    marker=False
    pushes=[]
    for _ in range(80):
        if prev is None:
            break
        ptxt=str(prev).lower()
        if '0x006a21bc' in ptxt:
            marker=True
        if prev.getMnemonicString().upper()=='PUSH':
            pushes.append((prev.getAddress(),str(prev)))
        prev=prev.getPrevious()
    if not marker:
        continue
    fn=fm.getFunctionContaining(ins.getAddress())
    name=fn.getName() if fn else '<no_function>'
    code=pushes[0][1] if pushes else '<none>'
    print('%s | %s | code=%s | %s' % (ins.getAddress(),name,code,ins))
    count+=1
print('TOTAL=%d' % count)
