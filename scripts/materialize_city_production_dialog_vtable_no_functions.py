#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()

targets = [0x00401E2E, 0x00406EB5]

print("=== materialize city production vtable no_function entries ===")
for t in targets:
    a = toAddr(t)
    fn = fm.getFunctionAt(a)
    if fn is not None:
        print("%s already function: %s" % (a, fn.getName()))
        continue
    disassemble(a)
    created = createFunction(a, None)
    fn2 = fm.getFunctionAt(a)
    if created and fn2 is not None:
        print("%s created: %s" % (a, fn2.getName()))
    else:
        print("%s create failed" % a)
