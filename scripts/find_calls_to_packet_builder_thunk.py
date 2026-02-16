#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

target = toAddr(0x00408d46)
print('=== calls to thunk_BuildTurnEventFactoryPacket (0x00408d46) ===')
for r in getReferencesTo(target):
    if r.getReferenceType() != RefType.UNCONDITIONAL_CALL:
        continue
    src = r.getFromAddress()
    fn = fm.getFunctionContaining(src)
    fnn = fn.getName() if fn else '<no_function>'
    ins = listing.getInstructionAt(src)
    prev = ins.getPrevious()
    window=[]
    pushes=[]
    for _ in range(20):
        if prev is None:
            break
        window.append((prev.getAddress(), str(prev)))
        if prev.getMnemonicString().upper()=='PUSH':
            pushes.append((prev.getAddress(), str(prev)))
        prev=prev.getPrevious()
    print('%s | %s' % (src, fnn))
    for a,t in reversed(window[:12]):
        print('  %s: %s' % (a,t))
print('=== done ===')
