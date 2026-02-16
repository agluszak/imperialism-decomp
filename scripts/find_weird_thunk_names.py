#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()

print("=== function names starting with 'Thunk' ===")
count = 0
for fn in fm.getFunctions(True):
    n = fn.getName()
    if n.startswith("Thunk"):
        print("%s %s" % (fn.getEntryPoint(), n))
        count += 1
print("count=%d" % count)
