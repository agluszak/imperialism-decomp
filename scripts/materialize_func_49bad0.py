#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
a = toAddr(0x0049BAD0)
fn = fm.getFunctionAt(a)
if fn is None:
    disassemble(a)
    createFunction(a, None)
    fn = fm.getFunctionAt(a)
print('function:', fn.getName() if fn else '<create_failed>')
