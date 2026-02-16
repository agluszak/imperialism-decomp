#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()

sites = [
    0x004851d3,
    0x00413d43,
    0x00413f81,
    0x00413a7a,
    0x0041444b,
    0x00414113,
    0x004143d5,
    0x0041515e,
    0x0041592d,
]

print("=== callsite -> containing function ===")
for s in sites:
    a = toAddr(s)
    fn = fm.getFunctionContaining(a)
    if fn is None:
        print("%s | <no_function>" % a)
        continue
    print("%s | %s @ %s" % (a, fn.getName(), fn.getEntryPoint()))
