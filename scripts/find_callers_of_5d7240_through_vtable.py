#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

# just list calls to thunk 0x00407702 and direct function 0x005d7240
for tgt,name in [(0x00407702,'thunk_DispatchGlobalTurnEventCode'),(0x005d7240,'DispatchGlobalTurnEventCode')]:
    print('=== refs to %s 0x%08x ===' % (name,tgt))
    for r in getReferencesTo(toAddr(tgt)):
        src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
    print('')
