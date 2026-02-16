#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType
fm=currentProgram.getFunctionManager()
for tgt in [0x005d5200,0x005d5250]:
    print('=== refs to 0x%08x ===' % tgt)
    for r in getReferencesTo(toAddr(tgt)):
        src=r.getFromAddress(); fn=fm.getFunctionContaining(src); fnn=fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (src, fnn, r.getReferenceType()))
    print('')
