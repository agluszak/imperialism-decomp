
void __thiscall FUN_0054d730(int *param_1,undefined4 param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  code *pcVar7;
  
  thunk_FUN_0048ab70(param_2);
  thunk_FUN_005430c0(param_1,1);
  iVar5 = *param_1;
  (**(code **)(iVar5 + 0x54))(3);
  g_pCursorControlPanel = (int *)(**(code **)(iVar5 + 0x94))(0x6c61626c);
  (**(code **)(*g_pCursorControlPanel + 0xc))();
  pcVar7 = (code *)0x0;
  (**(code **)(*g_pCursorControlPanel + 0x1e0))(0,0xe,0x2b6b);
  (**(code **)(*g_pCursorControlPanel + 0x204))(0x2b6b);
  (**(code **)(*g_pCursorControlPanel + 0x1c4))(1,0);
  thunk_FUN_005c4ab0(PTR_DAT_0065c160,0x6d61696e);
  iVar3 = 0x6e616d30;
  do {
    thunk_FUN_005c46b0(0x2742,6,iVar3 + 0x3fff700);
    thunk_FUN_005c46b0(0x2742,7,iVar3 + 0x207fe00);
    thunk_FUN_005c46b0(0x2742,8,iVar3);
    piVar2 = (int *)thunk_FUN_005c4310(iVar3,0,0xe,0x2b6b,0xfffffffe,s___computer___006980c8);
    (**(code **)(*piVar2 + 0xc))();
    thunk_ApplyUiTextStyleAndThemeFlags(piVar2,0,0xe,0x2b6b,0x2b6c);
    iVar4 = iVar3 + -0x6e616d2f;
    iVar3 = iVar3 + 1;
  } while (iVar4 < 7);
  thunk_FUN_005c46b0(0x2742,0xb,0x6d617020);
  thunk_FUN_005c46b0(0x2742,0xd,0x746e616d);
  thunk_FUN_005c46b0(0x2742,0xe,0x73656e64);
  cVar1 = thunk_FUN_0054a9d0();
  if (cVar1 == '\0') {
    thunk_FUN_005c46b0(0x2742,9,0x636e636c);
    thunk_FUN_005454b0(param_1);
    if (*(int *)(g_pLocalizationTable + 0x44) == 1) {
      thunk_FUN_0054c630();
      thunk_FUN_0054e4c0();
      thunk_FUN_0054b4c0(0xfffffff3,0,PTR_DAT_0065c160,PTR_DAT_0065c160);
      thunk_FUN_0054c8e0(0);
    }
    thunk_FUN_005c46b0(0x2742,0xc,0x6d657373);
  }
  else {
    thunk_RefreshNationStatusLabelsAndCodesForSlotOrAll(0xffffffff);
    iVar3 = thunk_FUN_0054b8c0(0xffffffff);
    if (iVar3 == 0x62757379) {
      uVar6 = 0x12;
    }
    else {
      uVar6 = 0x11;
    }
    thunk_FUN_005c46b0(0x2742,uVar6,0x636e636c);
    thunk_FUN_005c46b0(0x2742,0xc,0x6d657373);
    piVar2 = (int *)(*pcVar7)(0x636f6174);
    iVar3 = *piVar2;
    (**(code **)(iVar3 + 0xc))();
    iVar4 = thunk_GetActiveNationId(0);
    (**(code **)(iVar3 + 0x1c8))(iVar4 + 0x120a);
    (**(code **)(iVar3 + 0xa4))(1,0);
    iVar3 = thunk_FUN_0054b8c0(0xffffffff);
    if (iVar3 != 0x62757379) {
      (**(code **)(iVar5 + 0x1c8))(0x11f9,0);
    }
    thunk_FUN_0054e4c0();
  }
  param_1[0x25] = -1;
  (**(code **)(iVar5 + 0x4c))(1);
  cVar1 = thunk_FUN_0054a9d0();
  if (cVar1 == '\0') {
    iVar5 = (-(uint)(*(int *)(g_pLocalizationTable + 0x44) == 1) & 0xfffffff8) + 0x18;
  }
  else {
    iVar5 = thunk_FUN_0054b8c0(0xffffffff);
    iVar5 = (-(uint)(iVar5 != 0x62757379) & 0xffffffec) + 0x24;
  }
  uVar6 = (*(code *)0x2b6c)(0x6d657373,0,0xe,0x2b6c,1,0x2742,iVar5);
  thunk_FUN_005c4180(uVar6);
  thunk_FUN_0048ab70(pcVar7);
  return;
}

