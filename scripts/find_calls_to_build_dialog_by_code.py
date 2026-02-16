#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

target = toAddr(0x004357b0)
print('=== calls to BuildTurnEventDialogUiByCode (0x004357b0) ===')
for r in getReferencesTo(target):
    src = r.getFromAddress()
    fn = fm.getFunctionContaining(src)
    fnn = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
print('=== done ===')
