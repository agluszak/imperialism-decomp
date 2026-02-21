
undefined4 __thiscall FUN_0055f540(int param_1,short param_2)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  if (('\x01' << ((byte)param_2 & 0x1f) & *(byte *)(param_1 + 0x10)) != 0) {
    return 1;
  }
  uVar1 = *(uint *)(param_1 + 0x40);
  uVar2 = 0;
  if (uVar1 != 0) {
    do {
      if (uVar2 < uVar1) {
        puVar3 = (undefined4 *)(*(int *)(param_1 + 0x38) + uVar2 * 4);
      }
      else {
        puVar3 = (undefined4 *)0x0;
      }
      if (*(char *)*puVar3 == param_2) {
        return 1;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < uVar1);
  }
  return 0;
}

