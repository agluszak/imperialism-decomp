#@author codex
#@category Analysis

listing=currentProgram.getListing(); fm=currentProgram.getFunctionManager()

fn=fm.getFunctionContaining(toAddr(0x004357b0))
print('=== BuildTurnEventDialogUiByCode branch around 0x3B6 compare ===')
for ins in listing.getInstructions(fn.getBody(), True):
    a=ins.getAddress().getOffset()
    if 0x004357d0 <= a <= 0x00435930:
        print('%s: %s' % (ins.getAddress(), ins))
print('=== done ===')
