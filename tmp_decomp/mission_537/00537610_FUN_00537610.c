
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 __thiscall FUN_00537610(int *param_1,int param_2,int param_3)

{
  float fVar1;
  int iVar2;
  code *pcVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  char cVar7;
  short sVar8;
  int iVar9;
  undefined4 uVar10;
  uint uVar11;
  float *pfVar12;
  short sVar13;
  float10 fVar14;
  float local_10 [4];
  
  sVar8 = thunk_GetNavyOrderNormalizationBaseByNationType();
  if ((float)((int)*(short *)(param_2 + 0x1c) / (int)sVar8) < _DAT_0065aa20) {
    cVar7 = (**(code **)(*param_1 + 0x28))();
    if (cVar7 == '\0') {
      return (float10)_DAT_0065a9c4;
    }
  }
  iVar2 = *param_1;
  local_10[0] = 0.0;
  pcVar3 = *(code **)(iVar2 + 0xac);
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  iVar9 = (*pcVar3)();
  if (iVar9 == 0) {
    sVar8 = 0;
  }
  else {
    uVar10 = (*pcVar3)();
    sVar8 = thunk_FUN_00550550(uVar10);
  }
  sVar13 = 5;
  if (sVar8 < 6) {
    sVar13 = sVar8;
  }
  fVar1 = *(float *)(&DAT_006978f8 + ((int)sVar13 + (char)param_1[2] * 6) * 4);
  sVar8 = thunk_GetNavyOrderNormalizationBaseByNationType();
  fVar4 = (float)((int)*(short *)(param_2 + 0x1c) / (int)sVar8);
  uVar11 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[0] = (float)(int)(short)uVar11 * fVar4 + local_10[0];
  uVar11 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[1] = (float)(int)(short)uVar11 * fVar4 + local_10[1];
  uVar11 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  local_10[2] = (float)(int)(short)uVar11 * fVar4 + local_10[2];
  uVar11 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
  pfVar12 = local_10;
  iVar9 = 4;
  local_10[3] = (float)(int)(short)uVar11 + local_10[3];
  fVar4 = _DAT_0065a9e8;
  do {
    fVar4 = fVar4 + *pfVar12;
    pfVar12 = pfVar12 + 1;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  if (fVar4 == (float)_DAT_0065a9f0) {
    return (float10)_DAT_0065a9c4;
  }
  iVar9 = 4;
  pfVar12 = (float *)(param_3 + 0x14);
  fVar6 = _DAT_0065a9e8;
  do {
    iVar9 = iVar9 + -1;
    fVar5 = *(float *)(((int)local_10 - (param_3 + 0x14)) + (int)pfVar12) / fVar4 - *pfVar12;
    fVar6 = fVar5 * fVar5 + fVar6;
    pfVar12 = pfVar12 + 1;
  } while (iVar9 != 0);
  cVar7 = (**(code **)(iVar2 + 0x28))();
  if (cVar7 == '\0') {
    sVar8 = thunk_GetNavyOrderNormalizationBaseByNationType();
    if (*(short *)(param_2 + 0x1c) < sVar8) {
      sVar8 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar14 = ((float10)_DAT_0065aa08 - (float10)((int)*(short *)(param_2 + 0x1c) / (int)sVar8)) *
               (float10)_DAT_0065a9bc;
      goto LAB_0053780a;
    }
  }
  fVar14 = (float10)_DAT_0065a9f0;
LAB_0053780a:
  return -(fVar14 + (float10)fVar6 + (float10)fVar1);
}

