#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

print('=== CMP *,0x3B6 with branch context ===')
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper()!='CMP': continue
    if '0x3b6' not in str(ins).lower(): continue
    fn=fm.getFunctionContaining(ins.getAddress())
    fnn=fn.getName() if fn else '<no_function>'
    nxt=ins.getNext(); j='<none>'
    if nxt and nxt.getMnemonicString().upper().startswith('J'):
        j='%s: %s' % (nxt.getAddress(), nxt)
    print('%s | %s | %s | next=%s' % (ins.getAddress(), fnn, ins, j))
print('=== done ===')
