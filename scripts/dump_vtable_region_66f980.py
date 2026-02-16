#@author codex
#@category Analysis

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

bases = [0x0066f980, 0x0066f9a0, 0x0066f9c0, 0x0066f9dc, 0x0066fa0c]
for b in bases:
    base = toAddr(b)
    print('=== vtable-ish region base %s ===' % base)
    for i in range(24):
        a = base.add(i*4)
        try:
            data = listing.getDataAt(a)
            if data is None:
                createData(a, ghidra.program.model.data.PointerDataType())
                data = listing.getDataAt(a)
            v = data.getValue()
            if v is None:
                continue
            off = v.getOffset()
            targ = toAddr(off)
            fn = fm.getFunctionContaining(targ)
            fn_name = fn.getName() if fn else '<no_function>'
            print('[%02d] %s -> %s (%s)' % (i, a, targ, fn_name))
        except Exception:
            pass
    print('')
