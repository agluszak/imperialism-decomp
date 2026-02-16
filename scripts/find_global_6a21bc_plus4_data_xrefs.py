#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

refman = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

target = toAddr(0x006a21c0)  # g_pUiRuntimeContext + 4
print('=== references to absolute address 0x006A21C0 ===')
count = 0
for r in refman.getReferencesTo(target):
    src = r.getFromAddress()
    rt = r.getReferenceType()
    fn = fm.getFunctionContaining(src)
    fnn = fn.getName() if fn else '<no_function>'
    ins = listing.getInstructionAt(src)
    print('%s | %s | %s | %s' % (src, fnn, rt, ins if ins else '<no_insn>'))
    count += 1
print('TOTAL=%d' % count)
