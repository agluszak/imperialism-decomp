#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType
listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

target=toAddr(0x00407702)
print('=== calls to thunk_DispatchGlobalTurnEventCode (0x00407702) ===')
for r in getReferencesTo(target):
    if r.getReferenceType()!=RefType.UNCONDITIONAL_CALL:
        continue
    src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
    ins=listing.getInstructionAt(src)
    prev=ins.getPrevious(); pushes=[]
    for _ in range(16):
        if prev is None: break
        if prev.getMnemonicString().upper()=='PUSH': pushes.append((prev.getAddress(), str(prev)))
        prev=prev.getPrevious()
    arg0 = pushes[0][1] if pushes else '<none>'
    arg1 = pushes[1][1] if len(pushes)>1 else '<none>'
    print('%s | %s | arg0=%s | arg1=%s' % (src, fnn, arg0, arg1))
print('=== done ===')
