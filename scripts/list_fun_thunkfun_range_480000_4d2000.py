#@author codex
#@category Analysis

fm = currentProgram.getFunctionManager()
start = toAddr(0x00480000)
end_off = 0x004D2000

print("=== FUN_/thunk_FUN_ in range 0x00480000-0x004D2000 ===")
fun_count = 0
thunk_fun_count = 0
it = fm.getFunctions(start, True)
while it.hasNext():
    fn = it.next()
    off = fn.getEntryPoint().getOffset()
    if off >= end_off:
        break
    name = fn.getName()
    if name.startswith("FUN_"):
        print("FUN   %s %s" % (fn.getEntryPoint(), name))
        fun_count += 1
    elif name.startswith("thunk_FUN_"):
        print("THUNK %s %s" % (fn.getEntryPoint(), name))
        thunk_fun_count += 1
print("fun_count=%d thunk_fun_count=%d total=%d" % (fun_count, thunk_fun_count, fun_count + thunk_fun_count))
