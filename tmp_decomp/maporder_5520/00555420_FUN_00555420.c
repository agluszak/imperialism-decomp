
undefined4 __thiscall FUN_00555420(int *param_1,int *param_2)

{
  int *piVar1;
  char cVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  int iVar7;
  short sVar8;
  int iVar9;
  bool bVar10;
  int local_c [3];
  
  sVar6 = 0;
  if (param_1 != (int *)0x0) {
    sVar6 = 0;
    for (iVar7 = param_1[4]; iVar7 != 0; iVar7 = *(int *)(iVar7 + 4)) {
      sVar6 = sVar6 + 1;
    }
  }
  if (sVar6 != 0) {
    if (param_2 == (int *)0x0) {
      sVar6 = 0;
    }
    else {
      sVar6 = 0;
      for (iVar7 = param_2[4]; iVar7 != 0; iVar7 = *(int *)(iVar7 + 4)) {
        sVar6 = sVar6 + 1;
      }
    }
    if (sVar6 != 0) {
      if (((param_1[2] == 6) || (param_2[2] == 6)) || (param_2[2] == 5)) {
        bVar10 = true;
      }
      else {
        iVar7 = 0;
        iVar9 = 0;
        for (piVar1 = (int *)param_1[4]; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
          if ((char)piVar1[3] != '\0') {
            iVar7 = iVar7 + *(short *)(&DAT_00698124 + *(short *)(*piVar1 + 4) * 0x24);
            iVar9 = iVar9 + 1;
          }
        }
        if (iVar9 == 0) {
          sVar6 = 0;
        }
        else {
          sVar6 = (short)((iVar7 * 10) / iVar9);
        }
        sVar3 = thunk_CalculateMapOrderEntryAverageChildRatingX10();
        sVar8 = (sVar6 - sVar3) + 0x32;
        sVar4 = thunk_GetMapOrderEntryChildCount();
        sVar5 = thunk_GetMapOrderEntryChildCount();
        if (10 < (short)(sVar4 + sVar5)) {
          sVar8 = (sVar6 - sVar3) + 0x28 + sVar4 + sVar5;
        }
        iVar7 = GenerateThreadLocalRandom15();
        bVar10 = iVar7 % 100 < (int)sVar8;
      }
      goto LAB_0055552a;
    }
  }
  bVar10 = false;
LAB_0055552a:
  if (bVar10) {
    local_c[0] = 200;
    local_c[1] = 100;
    local_c[2] = 0x32;
    sVar6 = thunk_FUN_00556010();
    sVar8 = thunk_FUN_00556010();
    if (sVar6 * 100 < local_c[param_1[1]] * (int)sVar8) {
      local_c[0] = 200;
      local_c[1] = 100;
      local_c[2] = 0x32;
      sVar6 = thunk_FUN_00556010();
      sVar8 = thunk_FUN_00556010();
      if ((sVar6 * 100 < local_c[param_2[1]] * (int)sVar8) ||
         (*(char *)((int)param_2 + 0x26) != '\0')) {
        bVar10 = false;
      }
      else {
        cVar2 = thunk_FUN_00555c20(param_2);
        bVar10 = cVar2 == '\0';
      }
    }
    else {
      cVar2 = thunk_FUN_00555de0(param_1);
      if (cVar2 == '\0') {
        bVar10 = true;
      }
      else {
        cVar2 = thunk_FUN_00555c20(param_1);
        bVar10 = cVar2 == '\0';
      }
    }
    if (bVar10) {
      if (param_1 == (int *)0x0) {
        sVar6 = 0;
      }
      else {
        sVar6 = 0;
        for (iVar7 = param_1[4]; iVar7 != 0; iVar7 = *(int *)(iVar7 + 4)) {
          sVar6 = sVar6 + 1;
        }
      }
      if ((sVar6 != 0) && (sVar6 = thunk_GetMapOrderEntryChildCount(), sVar6 != 0)) {
        if ((*(short *)(g_pLocalizationTable + 0x4a) != 0) &&
           ((iVar7 = param_1[7], sVar6 = thunk_GetActiveNationId(), sVar6 == (short)iVar7 ||
            (iVar7 = param_2[7], sVar6 = thunk_GetActiveNationId(), sVar6 == (short)iVar7)))) {
          return 1;
        }
        thunk_ResolveMapOrderPairConflictStep(param_1,param_2);
      }
    }
  }
  return 0;
}

