#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

print('=== LB_SETITEMDATA / LB_GETITEMDATA callsites ===')
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper()!='PUSH':
        continue
    t=str(ins).lower().strip()
    if t not in ['push 0x19a','push 410','push 0x199','push 409']:
        continue
    fn=fm.getFunctionContaining(ins.getAddress()); fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
print('=== done ===')
