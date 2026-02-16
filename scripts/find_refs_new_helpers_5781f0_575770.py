#@author codex
#@category Analysis
ref=currentProgram.getReferenceManager(); fm=currentProgram.getFunctionManager()
for t in [0x005781f0,0x00575770,0x00545660,0x00593730,0x00593760,0x00593790]:
    a=toAddr(t)
    print('=== refs to %s ===' % a)
    rs=list(ref.getReferencesTo(a))
    if not rs: print('  none')
    for r in rs:
        src=r.getFromAddress(); fn=fm.getFunctionContaining(src)
        print('  from %s type=%s fn=%s' % (src,r.getReferenceType(),fn.getName() if fn else '<none>'))
    print('')
