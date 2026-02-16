#@author codex
#@category Analysis

from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()

addr_main = toAddr(0x004851b0)
addr_split = toAddr(0x0048542a)

fn_split = fm.getFunctionAt(addr_split)
if fn_split:
    removeFunction(fn_split)
    print('Removed split function at 0x0048542a')
else:
    print('No function-at split address')

fn_main = fm.getFunctionAt(addr_main)
if fn_main:
    removeFunction(fn_main)
    print('Removed main function at 0x004851b0')
else:
    print('No function-at main address')

new_fn = createFunction(addr_main, 'ShowCityViewSelectionDialog')
if new_fn:
    print('Created function:', new_fn.getName(), new_fn.getEntryPoint(), new_fn.getBody())
else:
    print('Failed to create function at 0x004851b0')
