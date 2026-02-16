#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()
fn=fm.getFunctionContaining(toAddr(0x005d7240))
print('=== DispatchGlobalTurnEventCode key event-slot writes ===')
for ins in listing.getInstructions(fn.getBody(), True):
    a=ins.getAddress().getOffset()
    if a in [0x005d7649,0x005d794c,0x005d75f3,0x005d7426,0x005d78d6]:
        print('%s: %s' % (ins.getAddress(), ins))
print('=== done ===')
