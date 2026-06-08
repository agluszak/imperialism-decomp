import sys
import capstone
import pefile

pe = pefile.PE("Imperialism.exe")
ep = pe.OPTIONAL_HEADER.ImageBase

def get_bytes(addr, size):
    for sec in pe.sections:
        start = ep + sec.VirtualAddress
        end = start + sec.Misc_VirtualSize
        if start <= addr < end:
            offset = addr - start
            return sec.get_data()[offset:offset+size]
    return b""

code = get_bytes(0x00491400, 100)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
for i in md.disasm(code, 0x00491400):
    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
    if i.mnemonic == "ret": break
