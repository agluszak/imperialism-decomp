#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== +0x4c dispatch sites with preceding 0x199 (LB_GETITEMDATA) pattern ===')
count=0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper()!='CALL':
        continue
    low=str(ins).lower()
    if '+ 0x4c]' not in low:
        continue

    prev=ins.getPrevious()
    window=[]
    has_199=False
    for _ in range(30):
        if prev is None:
            break
        txt=str(prev)
        window.append((prev.getAddress(),txt))
        if '0x199' in txt.lower():
            has_199=True
        prev=prev.getPrevious()
    if not has_199:
        continue
    fn=fm.getFunctionContaining(ins.getAddress())
    fn_name=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fn_name, ins))
    for a,t in reversed(window[:12]):
        print('  %s: %s' % (a,t))
    count+=1
print('TOTAL=%d' % count)
