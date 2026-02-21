
void __thiscall FUN_00552b90(int param_1,int *param_2)

{
  code *pcVar1;
  int *piVar2;
  int iVar3;
  short sVar4;
  undefined2 extraout_var;
  int iStack_44;
  undefined4 uStack_40;
  int iStack_3c;
  undefined4 uStack_38;
  undefined1 *puStack_34;
  undefined4 uStack_30;
  undefined1 *puStack_2c;
  undefined4 uStack_28;
  int *piStack_24;
  undefined4 uStack_20;
  int iStack_1c;
  int *piStack_18;
  
  piStack_18 = param_2;
  iStack_1c = 0x552ba1;
  thunk_HandleCityDialogNoOpSlot14();
  iStack_1c = param_1 + 4;
  piStack_18 = (int *)0x4;
  pcVar1 = *(code **)(*param_2 + 0x78);
  uStack_20 = 0x552bb0;
  (*pcVar1)();
  uStack_20 = 4;
  uStack_28 = 0x552bba;
  piStack_24 = (int *)(param_1 + 8);
  (*pcVar1)();
  if (*(int *)(param_1 + 8) == 5) {
    sVar4 = 0;
    do {
      if (*(int *)(g_pGlobalMapState + 0x10) + sVar4 * 0xa8 == *(int *)(param_1 + 0xc)) break;
      sVar4 = sVar4 + 1;
    } while (sVar4 < 0x180);
  }
  else {
    uStack_28 = 0x552bfc;
    thunk_GetShortAtOffset14OrInvalid();
  }
  puStack_2c = &stack0xfffffff4;
  uStack_28 = 2;
  uStack_30 = 0x552c0b;
  (*pcVar1)();
  uStack_30 = 0x552c13;
  thunk_GetShortAtOffset14OrInvalid();
  puStack_34 = &stack0xffffffec;
  uStack_30 = 2;
  uStack_38 = 0x552c22;
  (*pcVar1)();
  iStack_3c = param_1 + 0x1c;
  uStack_38 = 2;
  uStack_40 = 0x552c2c;
  (*pcVar1)();
  iStack_44 = param_1 + 0x26;
  uStack_40 = 1;
  (*pcVar1)();
  (*pcVar1)(param_1 + 0x30,2);
  if (param_1 == 0) {
    iStack_3c = 0;
  }
  else {
    iStack_3c = 0;
    for (iVar3 = *(int *)(param_1 + 0x10); iVar3 != 0; iVar3 = *(int *)(iVar3 + 4)) {
      iStack_3c = iStack_3c + 1;
    }
  }
  (*pcVar1)(&iStack_3c,2);
  for (piVar2 = *(int **)(param_1 + 0x10); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[1]) {
    iStack_3c = 0;
    for (iVar3 = g_pNavyPrimaryOrderList; (iVar3 != 0 && (iVar3 != *piVar2));
        iVar3 = *(int *)(iVar3 + 0x24)) {
      iStack_3c = iStack_3c + 1;
    }
    (*pcVar1)(&iStack_3c,2);
    iStack_44 = CONCAT22(extraout_var,(short)(char)piVar2[3]);
    (*pcVar1)(&iStack_44,2);
  }
  return;
}

