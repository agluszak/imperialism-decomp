#@author codex
#@category Analysis

fm=currentProgram.getFunctionManager()
listing=currentProgram.getListing()

print('=== instructions containing 3b6 textual literal ===')
for ins in listing.getInstructions(True):
    t=str(ins).lower()
    if '3b6' not in t:
        continue
    fn=fm.getFunctionContaining(ins.getAddress())
    fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
print('=== done ===')
