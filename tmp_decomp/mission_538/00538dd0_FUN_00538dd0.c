
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 __thiscall FUN_00538dd0(int param_1,int param_2)

{
  undefined2 uVar1;
  float fVar2;
  char cVar3;
  short sVar4;
  void *pvVar5;
  uint uVar6;
  float *pfVar7;
  int iVar8;
  short *psVar9;
  float10 fVar10;
  float10 fVar11;
  float10 fVar12;
  float local_10 [4];
  
  local_10[0] = 0.0;
  local_10[1] = 0.0;
  uVar1 = *(undefined2 *)(param_1 + 4);
  local_10[2] = 0.0;
  local_10[3] = 0.0;
  for (pvVar5 = thunk_GetNavyPrimaryOrderListHead(); pvVar5 != (void *)0x0;
      pvVar5 = *(void **)((int)pvVar5 + 0x24)) {
    if ((*(int *)((int)pvVar5 + 8) == param_2) &&
       (cVar3 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))
                          (uVar1,*(undefined2 *)((int)pvVar5 + 0x14)), cVar3 != '\0')) {
      sVar4 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar2 = (float)((int)*(short *)((int)pvVar5 + 0x1c) / (int)sVar4);
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[0] = (float)(int)(short)uVar6 * fVar2 + local_10[0];
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[1] = (float)(int)(short)uVar6 * fVar2 + local_10[1];
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[2] = (float)(int)(short)uVar6 * fVar2 + local_10[2];
      uVar6 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[3] = (float)(int)(short)uVar6 + local_10[3];
    }
  }
  fVar10 = (float10)_DAT_0065a9e8;
  pfVar7 = local_10;
  iVar8 = 4;
  do {
    fVar10 = fVar10 + (float10)*pfVar7;
    pfVar7 = pfVar7 + 1;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  if (fVar10 == (float10)_DAT_0065a9f0) {
    return (float10)_DAT_0065a9e8;
  }
  fVar11 = (float10)_DAT_0065a9e8;
  psVar9 = &DAT_00697958;
  pfVar7 = local_10;
  do {
    fVar12 = (float10)*pfVar7 / fVar10 - (float10)(int)*psVar9 * (float10)_DAT_0065a9f8;
    if (fVar12 <= (float10)_DAT_0065a9f0) {
      fVar12 = -fVar12;
    }
    fVar11 = fVar11 + fVar12;
    psVar9 = psVar9 + 1;
    pfVar7 = pfVar7 + 1;
  } while ((int)psVar9 < 0x697960);
  return fVar10 * ((float10)_DAT_0065aa08 - fVar11 * (float10)_DAT_0065aa00);
}

