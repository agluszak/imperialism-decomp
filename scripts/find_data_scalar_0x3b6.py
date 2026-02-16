#@category Imperialism.Analysis

from ghidra.program.model.scalar import Scalar

target = 0x3B6
listing = currentProgram.getListing()
refman = currentProgram.getReferenceManager()
funcman = currentProgram.getFunctionManager()

matches = 0
it = listing.getDefinedData(True)
while it.hasNext():
    d = it.next()
    val = d.getValue()
    sval = None
    if isinstance(val, Scalar):
        sval = val.getUnsignedValue()
    elif hasattr(val, 'getValue'):
        try:
            inner = val.getValue()
            if isinstance(inner, Scalar):
                sval = inner.getUnsignedValue()
        except:
            pass

    if sval == target:
        addr = d.getAddress()
        print("DATA %s | %s | 0x%X" % (addr, d.getDataType().getDisplayName(), sval))
        refs = refman.getReferencesTo(addr)
        had_ref = False
        while refs.hasNext():
            r = refs.next()
            from_addr = r.getFromAddress()
            f = funcman.getFunctionContaining(from_addr)
            fname = f.getName() if f else "<no_func>"
            print("  XREF from %s (%s) [%s]" % (from_addr, fname, r.getReferenceType()))
            had_ref = True
        if not had_ref:
            print("  XREF none")
        matches += 1

print("TOTAL_DATA_MATCHES=%d" % matches)
