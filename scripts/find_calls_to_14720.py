#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType
listing=currentProgram.getListing()
fm=currentProgram.getFunctionManager()

target=toAddr(0x00414720)
print('=== direct calls to PostTurnEventCodeMessage2420 (0x00414720) ===')
for r in getReferencesTo(target):
    if r.getReferenceType() != RefType.UNCONDITIONAL_CALL:
        continue
    src=r.getFromAddress()
    fn=fm.getFunctionContaining(src)
    fnn=fn.getName() if fn else '<no_function>'
    ins=listing.getInstructionAt(src)
    prev=ins.getPrevious()
    pushes=[]
    for _ in range(12):
        if prev is None:
            break
        if prev.getMnemonicString().upper()=='PUSH':
            pushes.append((prev.getAddress(), str(prev)))
        prev=prev.getPrevious()
    arg=pushes[0][1] if pushes else '<none>'
    print('%s | %s | arg=%s' % (src, fnn, arg))
print('=== done ===')
