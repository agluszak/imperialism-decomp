#@author codex
#@category Analysis

from ghidra.program.model.symbol import SourceType

entries = [
    (0x0040724d, 'thunk_NoOpTurnOrderNavigationVtableSlotA'),
    (0x00408832, 'thunk_NoOpTurnOrderNavigationVtableSlotB'),
]
fm = currentProgram.getFunctionManager()

for ea, name in entries:
    addr = toAddr(ea)
    fn = fm.getFunctionContaining(addr)
    if fn is None:
        createFunction(addr, name)
        fn = fm.getFunctionContaining(addr)
    if fn is not None:
        fn.setName(name, SourceType.USER_DEFINED)
        print('OK %s at %s' % (fn.getName(), fn.getEntryPoint()))
    else:
        print('FAIL at %s' % addr)
