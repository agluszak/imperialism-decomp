#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
print('=== refs to HandleDialogResultAndPostCommand100 (0x00413f60) ===')
for r in getReferencesTo(toAddr(0x00413f60)):
    src=r.getFromAddress()
    fn=fm.getFunctionContaining(src)
    fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
print('=== done ===')
