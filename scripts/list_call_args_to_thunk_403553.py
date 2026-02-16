#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
target = toAddr(0x00403553)
print('=== call args to thunk_FUN_00581870 (0x00403553) ===')
for ref in getReferencesTo(target):
    if ref.getReferenceType() != RefType.UNCONDITIONAL_CALL:
        continue
    src = ref.getFromAddress()
    ins = listing.getInstructionAt(src)
    fn = fm.getFunctionContaining(src)
    fn_name = fn.getName() if fn else '<no_function>'
    prev = ins.getPrevious()
    pushes = []
    window=[]
    for _ in range(12):
        if prev is None:
            break
        window.append((prev.getAddress(), str(prev)))
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), str(prev)))
        prev = prev.getPrevious()
    arg = pushes[0][1] if pushes else '<none>'
    print('%s | %s | arg=%s' % (src, fn_name, arg))
    for a,t in reversed(window[:6]):
        print('  %s: %s' % (a,t))
