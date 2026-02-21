
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 __fastcall FUN_00537f40(int *param_1)

{
  float fVar1;
  float fVar2;
  code *pcVar3;
  float fVar4;
  short sVar5;
  int iVar6;
  undefined4 uVar7;
  uint uVar8;
  float *pfVar9;
  float *pfVar10;
  int iVar11;
  int *piVar12;
  float10 fVar13;
  float10 fVar14;
  float local_10 [4];
  
  fVar2 = _DAT_0065a9e8;
  local_10[0] = 0.0;
  piVar12 = (int *)param_1[9];
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  if (piVar12 != (int *)0x0) {
    pcVar3 = *(code **)(*param_1 + 0xac);
    do {
      iVar11 = *piVar12;
      iVar6 = (*pcVar3)();
      if (iVar6 == 0) {
        sVar5 = 0;
      }
      else {
        uVar7 = (*pcVar3)();
        sVar5 = thunk_FUN_00550550(uVar7);
      }
      if (5 < sVar5) {
        sVar5 = 5;
      }
      fVar1 = *(float *)(&DAT_006978c8 + sVar5 * 4);
      sVar5 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar4 = fVar1 * (float)((int)*(short *)(iVar11 + 0x1c) / (int)sVar5);
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[0] = (float)(int)(short)uVar8 * fVar4 + local_10[0];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[1] = (float)(int)(short)uVar8 * fVar4 + local_10[1];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[2] = (float)(int)(short)uVar8 * fVar4 + local_10[2];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      piVar12 = (int *)piVar12[1];
      local_10[3] = (float)(int)(short)uVar8 * fVar1 + local_10[3];
    } while (piVar12 != (int *)0x0);
  }
  fVar14 = (float10)fVar2;
  fVar13 = (float10)fVar2;
  pfVar10 = local_10;
  iVar11 = 4;
  pfVar9 = (float *)(param_1 + 0xb);
  do {
    if (*pfVar9 < *pfVar10) {
      *pfVar10 = (*pfVar10 - *pfVar9) * _DAT_0065a960 + *pfVar9;
    }
    fVar2 = *pfVar10;
    pfVar10 = pfVar10 + 1;
    iVar11 = iVar11 + -1;
    fVar13 = fVar13 + (float10)*pfVar9;
    fVar14 = fVar14 + SQRT((float10)*pfVar9 * (float10)fVar2);
    pfVar9 = pfVar9 + 1;
  } while (iVar11 != 0);
  return fVar14 / fVar13;
}

