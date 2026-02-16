#@author codex
#@category Analysis

listing=currentProgram.getListing()
fm=currentProgram.getFunctionManager()
base=toAddr(0x00649d20)
print('=== table around 0x00649d20 ===')
for i in range(40):
    a=base.add(i*4)
    try:
        d=listing.getDataAt(a)
        if d is None:
            createData(a, ghidra.program.model.data.PointerDataType())
            d=listing.getDataAt(a)
        v=d.getValue()
        if v is None:
            continue
        t=toAddr(v.getOffset())
        fn=fm.getFunctionContaining(t)
        name=fn.getName() if fn else '<no_function>'
        print('[%02d] %s -> %s (%s)' % (i,a,t,name))
    except Exception:
        pass
