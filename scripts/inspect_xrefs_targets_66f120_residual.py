#@author codex
#@category Analysis

targets = [
    0x00485E90,
    0x00415CE0,
    0x005DCAA0,
    0x005D57B0,
    0x005DA040,
    0x005D8980,
    0x005D8CC0,
]

fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()

for t in targets:
    addr = toAddr(t)
    fn = fm.getFunctionContaining(addr)
    print("=== XREFS TO %s (%s) ===" % (addr, fn.getName() if fn else "<no_function>"))
    refs = rm.getReferencesTo(addr)
    count = 0
    for r in refs:
        frm = r.getFromAddress()
        from_fn = fm.getFunctionContaining(frm)
        print(
            "from %s %-12s type=%s fn=%s"
            % (
                frm,
                r.getReferenceType().getName(),
                " data" if r.getReferenceType().isData() else " code",
                from_fn.getName() if from_fn else "<none>",
            )
        )
        count += 1
    print("total refs: %d\n" % count)
