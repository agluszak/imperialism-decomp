#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager(); refman=currentProgram.getReferenceManager()

# look for string literal '3B6' or nearby known assert source string
for saddr in [0x00694290]:
    print('=== refs to string/data 0x%08x ===' % saddr)
    for r in refman.getReferencesTo(toAddr(saddr)):
        src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
    print('')
