
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 FUN_005389f0(undefined4 param_1,int param_2)

{
  float fVar1;
  char cVar2;
  short sVar3;
  void *pvVar4;
  uint uVar5;
  float *pfVar6;
  int iVar7;
  short *psVar8;
  float10 fVar9;
  float10 fVar10;
  float10 fVar11;
  float local_10 [4];
  
  local_10[0] = 0.0;
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  for (pvVar4 = thunk_GetNavyPrimaryOrderListHead(); pvVar4 != (void *)0x0;
      pvVar4 = *(void **)((int)pvVar4 + 0x24)) {
    if ((*(int *)((int)pvVar4 + 8) == param_2) &&
       (cVar2 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))
                          (param_1,*(undefined2 *)((int)pvVar4 + 0x14)), cVar2 != '\0')) {
      sVar3 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar1 = (float)((int)*(short *)((int)pvVar4 + 0x1c) / (int)sVar3);
      uVar5 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[0] = (float)(int)(short)uVar5 * fVar1 + local_10[0];
      uVar5 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[1] = (float)(int)(short)uVar5 * fVar1 + local_10[1];
      uVar5 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[2] = (float)(int)(short)uVar5 * fVar1 + local_10[2];
      uVar5 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[3] = (float)(int)(short)uVar5 + local_10[3];
    }
  }
  fVar9 = (float10)_DAT_0065a9e8;
  pfVar6 = local_10;
  iVar7 = 4;
  do {
    fVar9 = fVar9 + (float10)*pfVar6;
    pfVar6 = pfVar6 + 1;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  if (fVar9 == (float10)_DAT_0065a9f0) {
    return (float10)_DAT_0065a9e8;
  }
  fVar10 = (float10)_DAT_0065a9e8;
  psVar8 = &DAT_00697958;
  pfVar6 = local_10;
  do {
    fVar11 = (float10)*pfVar6 / fVar9 - (float10)(int)*psVar8 * (float10)_DAT_0065a9f8;
    if (fVar11 <= (float10)_DAT_0065a9f0) {
      fVar11 = -fVar11;
    }
    fVar10 = fVar10 + fVar11;
    psVar8 = psVar8 + 1;
    pfVar6 = pfVar6 + 1;
  } while ((int)psVar8 < 0x697960);
  return fVar9 * ((float10)_DAT_0065aa08 - fVar10 * (float10)_DAT_0065aa00);
}

