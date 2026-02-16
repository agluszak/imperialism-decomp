#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()
fn=fm.getFunctionContaining(toAddr(0x00485920))
print('=== HandleCustomMessage2420DispatchTurnEvent key window ===')
for ins in listing.getInstructions(fn.getBody(), True):
    a=ins.getAddress().getOffset()
    if 0x00485920 <= a <= 0x00485980:
        print('%s: %s' % (ins.getAddress(), ins))
print('=== done ===')
