#@author codex
#@category Analysis

fm=currentProgram.getFunctionManager()
for addr,name in [(0x005d7c40,'DispatchTurnEvent3B8AndWaitForCompletion'),(0x005d7090,'DispatchTurnEvent7D8AndUpdateMainViewSelection'),(0x005d7100,'DispatchTurnEvent7D8IfTurnFlowIdle')]:
    print('=== refs to %s 0x%08x ===' % (name,addr))
    for r in getReferencesTo(toAddr(addr)):
        src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
    print('')
