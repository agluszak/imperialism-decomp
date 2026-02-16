#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType
listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager(); target=toAddr(0x00408715)
print('=== callers with arg to thunk_PostTurnEventCodeMessage2420 ===')
for r in getReferencesTo(target):
    if r.getReferenceType()!=RefType.UNCONDITIONAL_CALL: continue
    src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
    ins=listing.getInstructionAt(src); prev=ins.getPrevious(); arg='<none>'
    for _ in range(8):
        if prev is None: break
        if prev.getMnemonicString().upper()=='PUSH': arg=str(prev); break
        prev=prev.getPrevious()
    print('%s | %s | arg=%s' % (src,fnn,arg))
print('=== done ===')
