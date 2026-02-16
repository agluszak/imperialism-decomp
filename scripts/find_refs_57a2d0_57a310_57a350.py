#@author codex
#@category Analysis
ref=currentProgram.getReferenceManager(); fm=currentProgram.getFunctionManager()
for t in [0x0057a2d0,0x0057a310,0x0057a350]:
    a=toAddr(t)
    print('=== refs to %s ===' % a)
    for r in ref.getReferencesTo(a):
        src=r.getFromAddress(); fn=fm.getFunctionContaining(src)
        print('  from %s type=%s fn=%s' % (src,r.getReferenceType(),fn.getName() if fn else '<none>'))
    print('')
