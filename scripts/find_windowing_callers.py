#@author codex
#@category Analysis

from collections import defaultdict

TARGET_IMPORTS = [
    "RegisterClassA",
    "CreateWindowExA",
    "ShowWindow",
    "UpdateWindow",
    "DestroyWindow",
    "DefWindowProcA",
    "GetMessageA",
    "TranslateMessage",
    "DispatchMessageA",
    "PeekMessageA",
    "PostMessageA",
    "SendMessageA",
    "SetWindowPos",
    "LoadIconA",
    "LoadCursorA",
]

st = currentProgram.getSymbolTable()
rm = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

def get_external_symbol_addrs(name):
    addrs = []
    it = st.getSymbols(name)
    while it.hasNext():
        sym = it.next()
        addr = sym.getAddress()
        if addr is None:
            continue
        space = addr.getAddressSpace()
        if space is not None and space.getName() == "EXTERNAL":
            addrs.append(addr)
    return addrs

by_func = {}

for imp_name in TARGET_IMPORTS:
    ext_addrs = get_external_symbol_addrs(imp_name)
    if len(ext_addrs) == 0:
        print("[missing import symbol] %s" % imp_name)
        continue

    for ext_addr in ext_addrs:
        refs = rm.getReferencesTo(ext_addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            fn = fm.getFunctionContaining(from_addr)
            if fn is None:
                continue
            faddr = fn.getEntryPoint()
            key = faddr.toString()
            if key not in by_func:
                by_func[key] = {
                    "addr": faddr,
                    "name": fn.getName(),
                    "imports": set(),
                    "sites": [],
                }
            by_func[key]["imports"].add(imp_name)
            by_func[key]["sites"].append((from_addr, imp_name))

rows = list(by_func.values())
rows.sort(key=lambda r: (-len(r["imports"]), r["name"], r["addr"].toString()))

print("=== Windowing API caller candidates ===")
for row in rows:
    imports = sorted(list(row["imports"]))
    score = len(imports)
    name = row["name"]
    # Focus output on high-signal functions + unnamed/generic helpers.
    if score < 2 and not name.startswith("FUN_"):
        continue
    print("%s %s imports=%d [%s]" % (row["addr"], name, score, ", ".join(imports)))

print("total_functions=%d" % len(rows))
