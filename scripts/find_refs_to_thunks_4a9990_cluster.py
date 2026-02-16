#@author codex
#@category Analysis

refman=currentProgram.getReferenceManager(); fm=currentProgram.getFunctionManager()
for t in [0x00408a03,0x00408657,0x00403986,0x00409903]:
    a=toAddr(t)
    print('=== refs to %s ===' % a)
    refs=list(refman.getReferencesTo(a))
    if not refs:
        print('  none')
    for r in refs:
        src=r.getFromAddress()
        fn=fm.getFunctionContaining(src)
        print('  from %s type=%s fn=%s' % (src,r.getReferenceType(),fn.getName() if fn else '<none>'))
    print('')
