#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

target = toAddr(0x00408715)  # thunk_PostTurnEventCodeMessage2420
print('=== callers of thunk_PostTurnEventCodeMessage2420 (0x00408715) ===')
for ref in getReferencesTo(target):
    if ref.getReferenceType() != RefType.UNCONDITIONAL_CALL:
        continue
    src = ref.getFromAddress()
    ins = listing.getInstructionAt(src)
    fn = fm.getFunctionContaining(src)
    fn_name = fn.getName() if fn else '<no_function>'

    # gather up to 8 previous instructions and collect pushes
    prev = ins.getPrevious()
    pushes = []
    window = []
    for _ in range(12):
        if prev is None:
            break
        ptxt = str(prev)
        window.append((prev.getAddress(), ptxt))
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), ptxt))
        prev = prev.getPrevious()

    arg = pushes[0][1] if pushes else '<none>'
    arg_addr = pushes[0][0] if pushes else None
    print('%s | %s | arg=%s @ %s' % (src, fn_name, arg, arg_addr))
    for a, t in reversed(window[:8]):
        print('  %s: %s' % (a, t))
print('=== end ===')
