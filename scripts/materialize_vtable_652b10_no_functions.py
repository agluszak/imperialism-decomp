#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

mem = currentProgram.getMemory()
fm = currentProgram.getFunctionManager()

base = toAddr(0x00652B10)
count = 32

print("=== materialize/map vtable 0x652B10 entries ===")
for i in range(count):
    slot = base.add(i * 4)
    ptr = mem.getInt(slot) & 0xffffffff
    ea = toAddr(ptr)

    fn = fm.getFunctionAt(ea)
    if fn is None:
        disassemble(ea)
        createFunction(ea, None)
        fn = fm.getFunctionAt(ea)

    fn_name = fn.getName() if fn else "<no_function>"

    target = None
    ins = getInstructionAt(ea)
    if ins and ins.getMnemonicString().upper() == "JMP":
        refs = getReferencesFrom(ea)
        for r in refs:
            if r.getReferenceType().isJump() and r.getToAddress().isMemoryAddress():
                target = r.getToAddress()
                break

    target_name = ""
    if target:
        tfn = fm.getFunctionAt(target)
        target_name = tfn.getName() if tfn else "<no_function>"
        print("[%02d] %s -> %s (%s) | target %s (%s)" % (i, slot, ea, fn_name, target, target_name))
    else:
        print("[%02d] %s -> %s (%s)" % (i, slot, ea, fn_name))
