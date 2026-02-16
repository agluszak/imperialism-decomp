#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()

targets = [
    0x00401113,
    0x0040154B,
    0x00409016,
    0x00409237,
    0x004082CE,
]

print("=== materialize armory-adjacent no_function thunks ===")
for t in targets:
    a = toAddr(t)
    fn = fm.getFunctionAt(a)
    if fn is None:
        disassemble(a)
        createFunction(a, None)
        fn = fm.getFunctionAt(a)
    if fn is None:
        print("%s create failed" % a)
    else:
        print("%s %s" % (a, fn.getName()))
