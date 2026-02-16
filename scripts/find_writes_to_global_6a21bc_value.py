#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

print('=== writes to global pointer DAT_006A21BC itself ===')
for ins in listing.getInstructions(True):
    t=str(ins).lower()
    if '0x006a21bc' not in t:
        continue
    if 'mov dword ptr [0x006a21bc],' in t or 'lea' in t:
        fn=fm.getFunctionContaining(ins.getAddress()); fnn=fn.getName() if fn else '<no_function>'
        print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
print('=== done ===')
