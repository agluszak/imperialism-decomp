#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

print('=== CMP against 0x3B6 near references to g_pUiRuntimeContext ===')
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper() != 'CMP':
        continue
    txt = str(ins).lower()
    if '0x3b6' not in txt:
        continue
    # look back for 0x006a21bc reference in window
    prev = ins.getPrevious()
    marker=False
    for _ in range(20):
        if prev is None:
            break
        if '0x006a21bc' in str(prev).lower():
            marker=True
            break
        prev = prev.getPrevious()
    if not marker:
        continue
    fn = fm.getFunctionContaining(ins.getAddress())
    fnn = fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
print('=== done ===')
