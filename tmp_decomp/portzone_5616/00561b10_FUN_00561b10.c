
undefined4 __thiscall FUN_00561b10(int param_1,short param_2)

{
  short sVar1;
  
  sVar1 = (short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + *(short *)(param_1 + 0x48) * 0x24
                          );
  return CONCAT31((int3)(CONCAT22((short)((uint)(*(short *)(param_1 + 0x48) * 9) >> 0x10),sVar1) >>
                        8),sVar1 == param_2);
}

