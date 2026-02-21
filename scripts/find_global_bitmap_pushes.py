#@category Imperialism
# Scan whole program for PUSH immediates matching target bitmap IDs.

from ghidra.program.model.scalar import Scalar

TARGETS = set([0x83f, 0x84d, 0x84f, 0x835, 0x836, 0x841])

listing = currentProgram.getListing()
inst_iter = listing.getInstructions(True)

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
    if val in TARGETS:
        f = getFunctionContaining(ins.getAddress())
        fname = f.getName() if f else "<no_func>"
        hits.append((ins.getAddress(), val, fname))

print("TARGETS", sorted(list(TARGETS)))
print("HITS", len(hits))
for addr, val, fname in hits:
    print("%s 0x%X %s" % (addr, val, fname))
