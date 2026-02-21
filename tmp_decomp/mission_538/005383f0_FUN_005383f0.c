
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 __thiscall FUN_005383f0(int *param_1,int param_2)

{
  float fVar1;
  code *pcVar2;
  float fVar3;
  float fVar4;
  short sVar5;
  int iVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  float *pfVar10;
  float *pfVar11;
  int *piVar12;
  float10 fVar13;
  float10 fVar14;
  float local_10 [4];
  
  local_10[0] = 0.0;
  piVar12 = (int *)param_1[9];
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  if (piVar12 != (int *)0x0) {
    pcVar2 = *(code **)(*param_1 + 0xac);
    do {
      iVar9 = *piVar12;
      iVar6 = (*pcVar2)();
      if (iVar6 == 0) {
        sVar5 = 0;
      }
      else {
        uVar7 = (*pcVar2)();
        sVar5 = thunk_FUN_00550550(uVar7);
      }
      if (5 < sVar5) {
        sVar5 = 5;
      }
      fVar1 = *(float *)(&DAT_006978c8 + sVar5 * 4);
      sVar5 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar3 = fVar1 * (float)((int)*(short *)(iVar9 + 0x1c) / (int)sVar5);
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[0] = (float)(int)(short)uVar8 * fVar3 + local_10[0];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[1] = (float)(int)(short)uVar8 * fVar3 + local_10[1];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[2] = (float)(int)(short)uVar8 * fVar3 + local_10[2];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      piVar12 = (int *)piVar12[1];
      local_10[3] = (float)(int)(short)uVar8 * fVar1 + local_10[3];
    } while (piVar12 != (int *)0x0);
  }
  pcVar2 = *(code **)(*param_1 + 0xac);
  iVar9 = (*pcVar2)();
  if (iVar9 == 0) {
    sVar5 = 0;
  }
  else {
    uVar7 = (*pcVar2)();
    sVar5 = thunk_FUN_00550550(uVar7);
  }
  if (5 < sVar5) {
    sVar5 = 5;
  }
  fVar1 = *(float *)(&DAT_006978c8 + sVar5 * 4);
  fVar4 = (float)_DAT_0065a9e0;
  sVar5 = thunk_GetNavyOrderNormalizationBaseByNationType();
  fVar3 = fVar1 * fVar4 * (float)((int)*(short *)(param_2 + 0x1c) / (int)sVar5);
  uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[0] = (float)(int)(short)uVar8 * fVar3 + local_10[0];
  uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[1] = (float)(int)(short)uVar8 * fVar3 + local_10[1];
  uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[2] = (float)(int)(short)uVar8 * fVar3 + local_10[2];
  uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  pfVar11 = local_10;
  iVar9 = 4;
  local_10[3] = (float)(int)(short)uVar8 * fVar1 * fVar4 + local_10[3];
  fVar13 = (float10)_DAT_0065a9e8;
  fVar14 = (float10)_DAT_0065a9e8;
  pfVar10 = (float *)(param_1 + 0xb);
  do {
    fVar1 = *pfVar11;
    pfVar11 = pfVar11 + 1;
    iVar9 = iVar9 + -1;
    fVar14 = fVar14 + (float10)*pfVar10;
    fVar13 = fVar13 + SQRT((float10)*pfVar10 * (float10)fVar1);
    pfVar10 = pfVar10 + 1;
  } while (iVar9 != 0);
  return fVar13 / fVar14;
}

