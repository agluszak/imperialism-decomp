
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 __thiscall FUN_00538120(int *param_1,int param_2)

{
  float fVar1;
  code *pcVar2;
  float fVar3;
  short sVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  float *pfVar9;
  float *pfVar10;
  int *piVar11;
  float10 fVar12;
  float10 fVar13;
  float local_10 [4];
  
  local_10[0] = 0.0;
  piVar11 = (int *)param_1[9];
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  if (piVar11 != (int *)0x0) {
    pcVar2 = *(code **)(*param_1 + 0xac);
    do {
      iVar8 = *piVar11;
      iVar5 = (*pcVar2)();
      if (iVar5 == 0) {
        sVar4 = 0;
      }
      else {
        uVar6 = (*pcVar2)();
        sVar4 = thunk_FUN_00550550(uVar6);
      }
      if (5 < sVar4) {
        sVar4 = 5;
      }
      fVar1 = *(float *)(&DAT_006978c8 + sVar4 * 4);
      sVar4 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar3 = fVar1 * (float)((int)*(short *)(iVar8 + 0x1c) / (int)sVar4);
      uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[0] = (float)(int)(short)uVar7 * fVar3 + local_10[0];
      uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[1] = (float)(int)(short)uVar7 * fVar3 + local_10[1];
      uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[2] = (float)(int)(short)uVar7 * fVar3 + local_10[2];
      uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      piVar11 = (int *)piVar11[1];
      local_10[3] = (float)(int)(short)uVar7 * fVar1 + local_10[3];
    } while (piVar11 != (int *)0x0);
  }
  pcVar2 = *(code **)(*param_1 + 0xac);
  iVar8 = (*pcVar2)();
  if (iVar8 == 0) {
    sVar4 = 0;
  }
  else {
    uVar6 = (*pcVar2)();
    sVar4 = thunk_FUN_00550550(uVar6);
  }
  if (5 < sVar4) {
    sVar4 = 5;
  }
  fVar1 = *(float *)(&DAT_006978c8 + sVar4 * 4);
  sVar4 = thunk_GetNavyOrderNormalizationBaseByNationType();
  fVar3 = fVar1 * (float)((int)*(short *)(param_2 + 0x1c) / (int)sVar4);
  uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[0] = (float)(int)(short)uVar7 * fVar3 + local_10[0];
  uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[1] = (float)(int)(short)uVar7 * fVar3 + local_10[1];
  uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[2] = (float)(int)(short)uVar7 * fVar3 + local_10[2];
  uVar7 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  pfVar10 = local_10;
  iVar8 = 4;
  local_10[3] = (float)(int)(short)uVar7 * fVar1 + local_10[3];
  fVar12 = (float10)_DAT_0065a9e8;
  fVar13 = (float10)_DAT_0065a9e8;
  pfVar9 = (float *)(param_1 + 0xb);
  do {
    fVar1 = *pfVar10;
    pfVar10 = pfVar10 + 1;
    iVar8 = iVar8 + -1;
    fVar13 = fVar13 + (float10)*pfVar9;
    fVar12 = fVar12 + SQRT((float10)*pfVar9 * (float10)fVar1);
    pfVar9 = pfVar9 + 1;
  } while (iVar8 != 0);
  return fVar12 / fVar13;
}

