
void __thiscall FUN_00552250(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  if (*(int *)(param_1 + 8) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 8) + 0x20) = 0;
    iVar1 = *(int *)(*(int *)(param_1 + 8) + 0xc);
    if (iVar1 != 0) {
      iVar2 = *(int *)(iVar1 + 0x10);
      *(undefined4 *)(iVar1 + 0x14) = 0;
      for (; iVar2 != 0; iVar2 = *(int *)(iVar2 + 4)) {
        uVar3 = thunk_FUN_00550670(*(undefined4 *)(iVar1 + 0x14),0);
        *(undefined4 *)(iVar1 + 0x14) = uVar3;
      }
    }
  }
  *(int *)(param_1 + 8) = param_2;
  if (param_2 != 0) {
    *(int *)(param_2 + 0x20) = param_1;
    iVar1 = *(int *)(*(int *)(param_1 + 8) + 0xc);
    if (iVar1 != 0) {
      iVar2 = *(int *)(iVar1 + 0x10);
      *(undefined4 *)(iVar1 + 0x14) = 0;
      for (; iVar2 != 0; iVar2 = *(int *)(iVar2 + 4)) {
        uVar3 = thunk_FUN_00550670(*(undefined4 *)(iVar1 + 0x14),0);
        *(undefined4 *)(iVar1 + 0x14) = uVar3;
      }
    }
  }
  return;
}

