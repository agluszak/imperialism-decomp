#@category Imperialism
# Extract PUSH immediates in 0x830..0x860 from trade initializer.

from ghidra.program.model.scalar import Scalar

FUNC_ADDR = 0x004601b0
LOW = 0x830
HIGH = 0x860

func = getFunctionAt(toAddr(FUNC_ADDR))
if func is None:
    print("ERR: function not found at 0x%08X" % FUNC_ADDR)
else:
    listing = currentProgram.getListing()
    inst_iter = listing.getInstructions(func.getBody(), True)
    hits = []
    for ins in inst_iter:
        if ins.getMnemonicString() != "PUSH":
            continue
        objs = ins.getOpObjects(0)
        if len(objs) != 1:
            continue
        obj = objs[0]
        if not isinstance(obj, Scalar):
            continue
        val = int(obj.getUnsignedValue())
        if LOW <= val <= HIGH:
            hits.append((ins.getAddress(), val))

    print("FUNC 0x%08X %s" % (FUNC_ADDR, func.getName()))
    print("HITS %d" % len(hits))
    for addr, val in hits:
        print("%s 0x%X" % (addr, val))
