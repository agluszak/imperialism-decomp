#@author codex
#@category Analysis

from ghidra.program.model.address import Address

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

base = toAddr(0x0066f120)
count = 64
ptr_size = currentProgram.getDefaultPointerSize()

print('=== vtable PTR_LAB_0066f120 entries ===')
for i in range(count):
    a = base.add(i * ptr_size)
    data = listing.getDataAt(a)
    if data is None:
        createData(a, ghidra.program.model.data.PointerDataType())
        data = listing.getDataAt(a)
    val = data.getValue()
    if val is None:
        continue
    try:
        targ = val.getOffset()
        targ_addr = toAddr(targ)
    except:
        continue
    fn = fm.getFunctionContaining(targ_addr)
    fn_name = fn.getName() if fn else '<no_function>'
    print('[%02d] %s (+0x%X) -> %s (%s)' % (i, a, i*ptr_size, targ_addr, fn_name))
