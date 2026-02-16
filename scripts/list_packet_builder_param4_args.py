#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
target = toAddr(0x00408d46)  # thunk_FUN_0048cf10

print('=== callers of thunk_FUN_0048cf10 (packet build with event code param_4) ===')
for ref in getReferencesTo(target):
    if ref.getReferenceType() != RefType.UNCONDITIONAL_CALL:
        continue
    src = ref.getFromAddress()
    ins = listing.getInstructionAt(src)
    fn = fm.getFunctionContaining(src)
    fn_name = fn.getName() if fn else '<no_function>'

    prev = ins.getPrevious()
    window = []
    pushes = []
    for _ in range(20):
        if prev is None:
            break
        txt = str(prev)
        window.append((prev.getAddress(), txt))
        if prev.getMnemonicString().upper() == 'PUSH':
            pushes.append((prev.getAddress(), txt))
        prev = prev.getPrevious()

    # For __thiscall with 6 pushed params, param_4 is usually 4th push from call-site tail.
    # pushes[0] is nearest to call, so param_4 approx pushes[3] if present.
    p4 = pushes[3][1] if len(pushes) > 3 else '<unknown>'
    print('%s | %s | approx_param4=%s' % (src, fn_name, p4))
    for a,t in reversed(window[:10]):
        print('  %s: %s' % (a,t))
print('=== end ===')
