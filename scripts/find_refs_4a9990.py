#@author codex
#@category Analysis

refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()
addr = toAddr(0x004a9990)
print('refs to', addr)
for r in refman.getReferencesTo(addr):
    src = r.getFromAddress()
    fn = fm.getFunctionContaining(src)
    print('%s type=%s fn=%s' % (src, r.getReferenceType(), fn.getName() if fn else '<none>'))
