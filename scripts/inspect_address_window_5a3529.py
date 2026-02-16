#@author codex
#@category Analysis

from ghidra.program.model.symbol import RefType

target = toAddr(0x005A56BE)
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

print("target:", target)
fn = fm.getFunctionContaining(target)
print("containing:", fn.getName() if fn else "<none>")

before = None
after = None
it = fm.getFunctions(True)
while it.hasNext():
    f = it.next()
    ep = f.getEntryPoint()
    if ep.compareTo(target) <= 0:
        before = f
    elif after is None:
        after = f
        break

if before:
    print("before:", before.getName(), "@", before.getEntryPoint())
if after:
    print("after:", after.getName(), "@", after.getEntryPoint())

print("=== instructions around target ===")
start = target.subtract(0x30)
end = target.add(0x30)
ins = listing.getInstructionAt(start)
if ins is None:
    ins = listing.getInstructionAfter(start)
while ins is not None and ins.getAddress().compareTo(end) <= 0:
    print("%s: %s" % (ins.getAddress(), ins))
    ins = ins.getNext()

print("=== refs to target ===")
for ref in getReferencesTo(target):
    print("from %s type=%s" % (ref.getFromAddress(), ref.getReferenceType()))
