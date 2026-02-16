#@author codex
#@category Analysis

listing=currentProgram.getListing()
fm=currentProgram.getFunctionManager()

print('=== writes to [reg+0x60] in 0x0048xxxx region ===')
for ins in listing.getInstructions(True):
    a=ins.getAddress().getOffset()
    if a < 0x00480000 or a >= 0x00490000:
        continue
    m=ins.getMnemonicString().upper()
    if m not in ('MOV','MOVSX','MOVZX','ADD','SUB','OR','AND','XOR','CMP'):
        continue
    txt=str(ins).lower()
    # rough memory dest/read pattern with +0x60
    if '+ 0x60]' not in txt and '+0x60]' not in txt:
        continue
    fn=fm.getFunctionContaining(ins.getAddress())
    name=fn.getName() if fn else '<no_function>'
    print('%s | %s | %s' % (ins.getAddress(),name,ins))
