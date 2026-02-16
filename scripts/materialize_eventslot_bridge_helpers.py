#@author codex
#@category Analysis

from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()

targets = [
    (0x004bc0b0, None),
    (0x00511e80, None),
    (0x00511ed0, None),
    (0x0058e1c0, None),
]

for addr_int, new_name in targets:
    addr = toAddr(addr_int)
    fn = fm.getFunctionContaining(addr)
    if fn is None:
        fn = createFunction(addr, None)
        print('CREATE %s -> %s' % (addr, fn.getName() if fn else 'None'))
    else:
        print('EXIST  %s -> %s' % (addr, fn.getName()))
    if fn and new_name:
        old = fn.getName()
        fn.setName(new_name, SourceType.USER_DEFINED)
        print('RENAME %s: %s -> %s' % (addr, old, new_name))
