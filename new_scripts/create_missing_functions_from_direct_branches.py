from ghidra.program.model.symbol import RefType

max_create = 20
if len(getScriptArgs()) > 0:
    try:
        max_create = int(getScriptArgs()[0])
    except Exception:
        pass

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
created = 0
seen = set()

ins_iter = listing.getInstructions(True)
while ins_iter.hasNext() and created < max_create:
    ins = ins_iter.next()
    m = ins.getMnemonicString().upper()
    if m not in ("CALL", "JMP"):
        continue
    flows = ins.getFlows()
    if flows is None or len(flows) != 1:
        continue
    dst = flows[0]
    if dst in seen:
        continue
    seen.add(dst)
    block = currentProgram.getMemory().getBlock(dst)
    if block is None or not block.isExecute():
        continue
    if fm.getFunctionContaining(dst) is not None:
        continue
    # Skip obvious external/overlay-like addresses
    if str(dst).startswith("EXTERNAL"):
        continue
    ok = disassemble(dst)
    if not ok:
        continue
    fn = createFunction(dst, None)
    if fn is None:
        continue
    created += 1
    print("CREATED %s @ %s from %s" % (fn.getName(), dst, ins.getAddress()))

print("TOTAL_CREATED %d" % created)
