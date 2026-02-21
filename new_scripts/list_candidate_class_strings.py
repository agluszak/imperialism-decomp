import re

pat = re.compile(r"(class|window|wnd|dialog|frame)", re.IGNORECASE)
listing = currentProgram.getListing()
mem = currentProgram.getMemory()
symtab = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()

min_len = 4
try:
    if len(getScriptArgs()) > 0:
        min_len = int(getScriptArgs()[0])
except Exception:
    pass

seen = set()
rows = []
for s in currentProgram.getSymbolTable().getAllSymbols(True):
    addr = s.getAddress()
    d = listing.getDataAt(addr)
    if d is None:
        continue
    v = d.getValue()
    if v is None:
        continue
    txt = str(v)
    if len(txt) < min_len:
        continue
    if not pat.search(txt):
        continue
    if addr in seen:
        continue
    seen.add(addr)
    refs = getReferencesTo(addr)
    callers = set()
    for r in refs:
        f = fm.getFunctionContaining(r.getFromAddress())
        if f is not None:
            callers.add("%s@%s" % (f.getName(), f.getEntryPoint()))
    rows.append((addr, txt, len(refs), sorted(callers)[:4]))

rows.sort(key=lambda x: (x[2], len(x[1])), reverse=True)
for addr, txt, rc, callers in rows[:200]:
    print("0x%s | %s | refs=%d | callers=%s" % (addr, txt, rc, ";".join(callers)))
