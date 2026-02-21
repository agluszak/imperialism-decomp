args = getScriptArgs()
if len(args) < 1:
    print("usage: <addr_hex>")
else:
    a = toAddr(args[0])
    mem = currentProgram.getMemory()
    listing = currentProgram.getListing()
    d = listing.getDataAt(a)
    print("ADDR %s" % a)
    b = mem.getBlock(a)
    if b is None:
        print("BLOCK <none>")
    else:
        print("BLOCK %s exec=%s write=%s init=%s" % (b.getName(), b.isExecute(), b.isWrite(), b.isInitialized()))
    print("DATA %s" % ("<none>" if d is None else d))
    print("VALUE %s" % ("<none>" if d is None else d.getValue()))
    try:
        p = getInt(a) & 0xffffffff
        print("DWORD 0x%08x" % p)
    except Exception as ex:
        print("DWORD_ERR %s" % ex)
