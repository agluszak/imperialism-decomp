args = getScriptArgs()
if not args:
    print("usage: <addr_hex> [addr_hex...]")
else:
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()
    for token in args:
        try:
            addr = toAddr(token)
        except Exception:
            print("BAD_ADDR: %s" % token)
            continue
        data = listing.getDataAt(addr)
        val = "<no_data>" if data is None else str(data.getValue())
        print("ADDR %s DATA %s" % (addr, val))
        syms = symtab.getSymbols(addr)
        if syms is None or len(syms) == 0:
            print("  SYM <none>")
            continue
        for s in syms:
            print("  SYM %s type=%s" % (s.getName(), s.getSymbolType()))
