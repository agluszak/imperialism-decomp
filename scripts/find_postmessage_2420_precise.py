#@author codex
#@category Analysis

import re
listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

# look for push 0x2420 then call thunk_PostTurnEventCodeMessage2420 or PostMessageA import call
print('=== push 0x2420 occurrences and containing function ===')
count=0
for ins in listing.getInstructions(True):
    if ins.getMnemonicString().upper()!='PUSH': continue
    t=str(ins).lower().strip()
    if t!='push 0x2420' and t!='push 9248': continue
    fn=fm.getFunctionContaining(ins.getAddress()); fnn=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(), fnn, ins))
    count+=1
print('TOTAL=%d' % count)
