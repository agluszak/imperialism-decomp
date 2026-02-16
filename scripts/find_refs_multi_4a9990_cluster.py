#@author codex
#@category Analysis

refman=currentProgram.getReferenceManager()
fm=currentProgram.getFunctionManager()
for t in [0x0048b5f0,0x0048a280,0x004a9ca0,0x00409d03]:
    addr=toAddr(t)
    print('=== refs to %s ===' % addr)
    refs=list(refman.getReferencesTo(addr))
    if not refs:
        print('  none')
    for r in refs:
        src=r.getFromAddress()
        fn=fm.getFunctionContaining(src)
        print('  from %s type=%s fn=%s' % (src,r.getReferenceType(),fn.getName() if fn else '<none>'))
    print('')
