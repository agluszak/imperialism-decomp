
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 FUN_00538bf0(short param_1,int param_2)

{
  float fVar1;
  short sVar2;
  void *pvVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  short *psVar7;
  float10 fVar8;
  float10 fVar9;
  float10 fVar10;
  float local_10 [4];
  
  local_10[0] = 0.0;
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  for (pvVar3 = thunk_GetNavyPrimaryOrderListHead(); pvVar3 != (void *)0x0;
      pvVar3 = *(void **)((int)pvVar3 + 0x24)) {
    if ((*(int *)((int)pvVar3 + 8) == param_2) && (param_1 == *(short *)((int)pvVar3 + 0x14))) {
      sVar2 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar1 = (float)((int)*(short *)((int)pvVar3 + 0x1c) / (int)sVar2);
      uVar4 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[0] = (float)(int)(short)uVar4 * fVar1 + local_10[0];
      uVar4 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[1] = (float)(int)(short)uVar4 * fVar1 + local_10[1];
      uVar4 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[2] = (float)(int)(short)uVar4 * fVar1 + local_10[2];
      uVar4 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[3] = (float)(int)(short)uVar4 + local_10[3];
    }
  }
  fVar8 = (float10)_DAT_0065a9e8;
  pfVar5 = local_10;
  iVar6 = 4;
  do {
    fVar8 = fVar8 + (float10)*pfVar5;
    pfVar5 = pfVar5 + 1;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  if (fVar8 == (float10)_DAT_0065a9f0) {
    return (float10)_DAT_0065a9e8;
  }
  fVar9 = (float10)_DAT_0065a9e8;
  psVar7 = &DAT_00697958;
  pfVar5 = local_10;
  do {
    fVar10 = (float10)*pfVar5 / fVar8 - (float10)(int)*psVar7 * (float10)_DAT_0065a9f8;
    if (fVar10 <= (float10)_DAT_0065a9f0) {
      fVar10 = -fVar10;
    }
    fVar9 = fVar9 + fVar10;
    psVar7 = psVar7 + 1;
    pfVar5 = pfVar5 + 1;
  } while ((int)psVar7 < 0x697960);
  return fVar8 * ((float10)_DAT_0065aa08 - fVar9 * (float10)_DAT_0065aa00);
}

