
uint __fastcall FUN_00538900(int *param_1)

{
  bool bVar1;
  char cVar2;
  bool bVar3;
  short sVar4;
  int *piVar5;
  int iVar6;
  undefined4 uVar7;
  
  bVar1 = false;
  iVar6 = 0;
  piVar5 = &g_pTerrainTypeDescriptorTable;
  do {
    if (bVar1) goto LAB_0053894a;
    if ((int *)*piVar5 != (int *)0x0) {
      if (iVar6 != (short)param_1[1]) {
        cVar2 = (**(code **)(*(int *)*piVar5 + 0x5c))((int)(short)param_1[1]);
        if (cVar2 == '\0') goto LAB_0053893a;
      }
      bVar3 = thunk_ContainsPointerArrayEntryMatchingByteKey();
      if (bVar3) {
        bVar1 = true;
      }
    }
LAB_0053893a:
    piVar5 = piVar5 + 1;
    iVar6 = iVar6 + 1;
  } while ((int)piVar5 < 0x6a436c);
  if (!bVar1) {
    (**(code **)(*(int *)(&g_apNationStates)[(short)param_1[1]] + 0xc))();
    uVar7 = 0;
    sVar4 = thunk_GetShortAtOffset14OrInvalid(0);
    thunk_FUN_004e8bf0((int)sVar4,uVar7);
    return 0;
  }
LAB_0053894a:
  if ((int *)param_1[6] != (int *)0x0) {
    cVar2 = (**(code **)(*(int *)param_1[6] + 0x38))();
    if (cVar2 != '\0') {
      cVar2 = (**(code **)(*(int *)param_1[6] + 0x40))((short)param_1[1]);
      if (cVar2 == '\0') {
        iVar6 = (**(code **)(*param_1 + 0xa0))();
        param_1[6] = iVar6;
      }
    }
  }
  return -(uint)(param_1[6] != 0) & (uint)param_1;
}

