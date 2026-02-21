
int * __fastcall FUN_00555090(int *param_1)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  short sVar4;
  
  if (param_1 == (int *)0x0) {
    return (int *)0x0;
  }
  sVar4 = 0;
  for (iVar3 = param_1[4]; iVar3 != 0; iVar3 = *(int *)(iVar3 + 4)) {
    sVar4 = sVar4 + 1;
  }
  if (sVar4 < 1) {
    piVar2 = (int *)thunk_FUN_00555090();
    (**(code **)(*param_1 + 0x1c))();
    return piVar2;
  }
  switch(param_1[2]) {
  case 0:
  case 1:
  case 4:
  case 7:
  case 8:
    goto switchD_005550d1_caseD_0;
  default:
switchD_005550d1_caseD_2:
    thunk_FUN_00555090();
    return param_1;
  case 5:
    iVar3 = thunk_GetCityIndexFromCityStatePointer(param_1[3]);
    cVar1 = *(char *)(*(int *)(g_pGlobalMapState + 0x10) + iVar3 * 0xa8);
    cVar1 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))
                      (CONCAT22(cVar1 >> 7,(short)param_1[7]),(int)cVar1);
    if (cVar1 != '\0') goto switchD_005550d1_caseD_2;
switchD_005550d1_caseD_0:
    piVar2 = (int *)thunk_FUN_00555090();
    (**(code **)(*param_1 + 0x1c))();
    return piVar2;
  }
}

