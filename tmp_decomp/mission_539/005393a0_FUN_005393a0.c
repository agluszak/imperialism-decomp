
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __fastcall FUN_005393a0(int param_1)

{
  undefined2 uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  short sVar6;
  void *pvVar7;
  uint uVar8;
  float *pfVar9;
  short *psVar10;
  int iVar11;
  float local_10 [4];
  
  local_10[0] = 0.0;
  local_10[1] = 0.0;
  local_10[2] = 0.0;
  iVar11 = *(int *)(param_1 + 0x14);
  uVar1 = *(undefined2 *)(param_1 + 4);
  local_10[3] = 0.0;
  for (pvVar7 = thunk_GetNavyPrimaryOrderListHead(); pvVar7 != (void *)0x0;
      pvVar7 = *(void **)((int)pvVar7 + 0x24)) {
    if ((*(int *)((int)pvVar7 + 8) == iVar11) &&
       (cVar5 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))
                          (uVar1,*(undefined2 *)((int)pvVar7 + 0x14)), cVar5 != '\0')) {
      sVar6 = thunk_GetNavyOrderNormalizationBaseByNationType();
      fVar2 = (float)((int)*(short *)((int)pvVar7 + 0x1c) / (int)sVar6);
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[0] = (float)(int)(short)uVar8 * fVar2 + local_10[0];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[1] = (float)(int)(short)uVar8 * fVar2 + local_10[1];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[2] = (float)(int)(short)uVar8 * fVar2 + local_10[2];
      uVar8 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
      local_10[3] = (float)(int)(short)uVar8 + local_10[3];
    }
  }
  pfVar9 = local_10;
  iVar11 = 4;
  fVar2 = _DAT_0065a9e8;
  do {
    fVar2 = fVar2 + *pfVar9;
    pfVar9 = pfVar9 + 1;
    iVar11 = iVar11 + -1;
  } while (iVar11 != 0);
  fVar3 = _DAT_0065a9e8;
  if (fVar2 != (float)_DAT_0065a9f0) {
    psVar10 = &DAT_00697958;
    pfVar9 = local_10;
    do {
      fVar4 = *pfVar9 / fVar2 - (float)(int)*psVar10 * (float)_DAT_0065a9f8;
      if (fVar4 <= (float)_DAT_0065a9f0) {
        fVar4 = -fVar4;
      }
      fVar3 = fVar3 + fVar4;
      psVar10 = psVar10 + 1;
      pfVar9 = pfVar9 + 1;
    } while ((int)psVar10 < 0x697960);
    fVar3 = fVar2 * ((float)_DAT_0065aa08 - fVar3 * (float)_DAT_0065aa00);
  }
  fVar2 = fVar3 * _DAT_0065a8fc;
  if (fVar3 * _DAT_0065a8fc == (float)_DAT_0065a9f0) {
    fVar2 = _DAT_0065aa24;
  }
  psVar10 = &DAT_00697958;
  pfVar9 = (float *)(param_1 + 0x2c);
  do {
    sVar6 = *psVar10;
    psVar10 = psVar10 + 1;
    *pfVar9 = (float)(int)sVar6 * fVar2 * (float)_DAT_0065a9f8;
    pfVar9 = pfVar9 + 1;
  } while ((int)psVar10 < 0x697960);
  return;
}

