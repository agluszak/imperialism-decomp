#@author codex
#@category Analysis

fm=currentProgram.getFunctionManager()
for addr,name in [(0x00413d20,'ShowNationSelectDialogAndRedispatchCurrentTurnEvent'),(0x004851b0,'ShowCityViewSelectionDialog'),(0x00485920,'HandleCustomMessage2420DispatchTurnEvent')]:
    print('=== refs to %s 0x%08x ===' % (name,addr))
    for r in getReferencesTo(toAddr(addr)):
        src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
    print('')
