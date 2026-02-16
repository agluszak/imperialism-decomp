#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

thunks = [0x00401ded,0x00401a5a,0x00401b18,0x004034c7,0x00403954,0x00406659,0x00406e38,0x004099f8,0x0040347c,0x0040264e,0x004082b0,0x0040873d,0x00408aa3,0x00402d79]
print('=== runtime-selection thunk map ===')
for t in thunks:
    a = toAddr(t)
    ins = listing.getInstructionAt(a)
    if ins is None:
        print('%s: <no instruction>' % a)
        continue
    txt = str(ins)
    target = None
    if ins.getMnemonicString().upper() == 'JMP':
        # parse immediate if present
        low = txt.lower()
        if '0x' in low:
            try:
                hx = low.split('0x',1)[1].split()[0]
                hx = ''.join(ch for ch in hx if ch in '0123456789abcdef')
                target = int(hx,16)
            except Exception:
                pass
    if target is not None:
        targ_addr = toAddr(target)
        fn = fm.getFunctionContaining(targ_addr)
        fn_name = fn.getName() if fn else '<no_function>'
        print('%s: %s -> %s (%s)' % (a, txt, targ_addr, fn_name))
    else:
        print('%s: %s' % (a, txt))
