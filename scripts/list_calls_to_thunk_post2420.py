#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

target = toAddr(0x00408715)
print('=== calls to thunk_PostTurnEventCodeMessage2420 (0x00408715) short list ===')
for r in getReferencesTo(target):
    if r.getReferenceType() != RefType.UNCONDITIONAL_CALL:
        continue
    src = r.getFromAddress()
    fn = fm.getFunctionContaining(src)
    fnn = fn.getName() if fn else '<no_function>'
    print('%s | %s' % (src, fnn))
print('=== done ===')
