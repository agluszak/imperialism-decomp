#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
print('=== callers of ShowNationSelectDialogAndRedispatchCurrentTurnEvent (0x00413d20) ===')
for r in getReferencesTo(toAddr(0x00413d20)):
    src = r.getFromAddress()
    fn = fm.getFunctionContaining(src)
    fnn = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
print('=== done ===')
