
undefined4 __thiscall FUN_0055f440(int param_1,short param_2)

{
  int *piVar1;
  uint uVar2;
  
  uVar2 = 0;
  if (*(uint *)(param_1 + 0x40) == 0) {
    return 0;
  }
  piVar1 = *(int **)(param_1 + 0x38);
  do {
    if (*piVar1 == *(int *)(g_pGlobalMapState + 0x10) + param_2 * 0xa8) {
      piVar1 = *(int **)(param_1 + 0x38) + uVar2;
      return CONCAT31((int3)((uint)piVar1 >> 8),piVar1 != (int *)0x0);
    }
    uVar2 = uVar2 + 1;
    piVar1 = piVar1 + 1;
  } while (uVar2 < *(uint *)(param_1 + 0x40));
  return 0;
}

