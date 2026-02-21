
void __thiscall FUN_0054e1f0(int *param_1,int param_2,int *param_3,undefined4 param_4)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  char cVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  
  if (param_2 == 0x29a) {
    piVar5 = (int *)(**(code **)(*param_1 + 0x94))(0x6f6b6179);
    iVar6 = *piVar5;
    (**(code **)(iVar6 + 0xc))();
    (**(code **)(iVar6 + 0xa8))(0,0);
    (**(code **)(iVar6 + 0xa4))(0,0);
  }
  if (param_2 == 0x7069636b) {
    (**(code **)(*param_3 + 0xc))();
    thunk_TryInvokeNationStateReplacementForSlot(param_3[0x1b]);
  }
  if ((((param_2 != 0x14) && (param_2 != 10)) && (param_2 != 0x22)) && (param_2 != 0xd))
  goto LAB_0054e36b;
  uVar1 = param_3[7];
  if (uVar1 < 0x636e636d) {
    if ((uVar1 == 0x636e636c) || (uVar1 == 0x63616e63)) {
      cVar4 = thunk_FUN_0054a9d0();
      if (cVar4 == '\0') {
        bVar3 = false;
        iVar6 = 0x48;
        do {
          iVar2 = *(int *)(g_pGameFlowState + iVar6);
          if ((iVar2 != 0) && (iVar7 = thunk_FUN_00549240(), iVar2 != iVar7)) {
            bVar3 = true;
          }
          iVar6 = iVar6 + 4;
        } while (iVar6 < 100);
        if (((g_pLocalizationTable[0x11] != 1) || (!bVar3)) ||
           (cVar4 = thunk_FUN_005deb40(0x6367616d), cVar4 != '\0')) {
          if (g_pLocalizationTable[0x11] == 1) {
            thunk_FUN_0054a340(0x6367616d,0xffffffff,0xfffffffe);
          }
          thunk_ResetLocalUiStateAndPostTurnEvent5E5();
        }
      }
      else {
        iVar6 = thunk_FUN_0054b8c0(0xffffffff);
        if (iVar6 == 0x62757379) {
          (**(code **)(*g_pLocalizationTable + 0x44))();
        }
        else {
          cVar4 = thunk_FUN_005deb40(0x6e657767);
          if (cVar4 != '\0') {
            thunk_FUN_0049e500();
          }
        }
      }
      goto LAB_0054e36b;
    }
  }
  else {
    if (uVar1 == 0x6a656469) {
      thunk_FUN_00544720();
      goto LAB_0054e36b;
    }
    if (uVar1 == 0x6f6b6179) {
      thunk_FUN_005456a0();
      goto LAB_0054e36b;
    }
    if (uVar1 == 0x73656e64) {
      thunk_FUN_0054b0f0(0xffffffff);
      goto LAB_0054e36b;
    }
  }
  if ((uVar1 < 0x72616430) || (0x72616436 < uVar1)) {
    if ((uVar1 < 0x6e616d30) || (0x6e616d36 < uVar1)) {
      if ((0x70696b2f < uVar1) && (uVar1 < 0x70696b37)) {
        thunk_TryInvokeNationStateReplacementForSlot(uVar1 + 0x8f9694d0);
      }
    }
    else {
      thunk_TryInvokeNationStateReplacementForSlot(uVar1 + 0x919e92d0);
    }
  }
  else {
    thunk_TryInvokeNationStateReplacementForSlot(uVar1 + 0x8d9e9bd0);
  }
LAB_0054e36b:
  thunk_HandleCityDialogToggleCommandOrForward(param_2,param_3,param_4);
  return;
}

