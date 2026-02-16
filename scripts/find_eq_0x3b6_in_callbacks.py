#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

targets = [0x004357b0,0x00491cc0,0x00491d80,0x0048cfd0]
for t in targets:
    fn = fm.getFunctionContaining(toAddr(t))
    if not fn:
        print('missing function at 0x%08x' % t)
        continue
    print('=== %s @ %s ===' % (fn.getName(), fn.getEntryPoint()))
    for ins in listing.getInstructions(fn.getBody(), True):
        txt = str(ins).lower()
        if '0x3b6' in txt:
            print('  %s: %s' % (ins.getAddress(), ins))
    print('')
