
int __thiscall FUN_00536840(int *param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  int local_20;
  
  iVar4 = param_1[9];
  local_20 = 0;
  if (iVar4 != 0) {
    pcVar1 = *(code **)(*param_1 + 0xac);
    do {
      iVar2 = (*pcVar1)();
      if (iVar2 != 0) {
        uVar3 = (*pcVar1)();
        thunk_FUN_00550550(uVar3);
      }
      thunk_GetNavyOrderNormalizationBaseByNationType();
      thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      iVar4 = *(int *)(iVar4 + 4);
    } while (iVar4 != 0);
  }
  iVar4 = 4;
  piVar5 = (int *)(param_2 + 0x14);
  do {
    iVar2 = __ftol();
    *piVar5 = iVar2;
    local_20 = local_20 + iVar2;
    piVar5 = piVar5 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  return local_20;
}

