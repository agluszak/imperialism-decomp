
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __fastcall FUN_00538fe0(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  char cVar6;
  short sVar7;
  int iVar8;
  void *pvVar9;
  uint uVar10;
  float *pfVar11;
  short *psVar12;
  float local_10 [4];
  
  iVar8 = FindFirstPortZoneContextByNation(*(undefined2 *)(param_1 + 4));
  if (*(int *)(iVar8 + 0x2c) == 0) {
    pvVar9 = ReallocateHeapBlockWithAllocatorTracking();
    if (pvVar9 == (void *)0x0) {
      pvVar9 = ReallocateHeapBlockWithAllocatorTracking();
      *(void **)(iVar8 + 0x28) = pvVar9;
      *(undefined4 *)(iVar8 + 0x2c) = 1;
    }
    else {
      *(void **)(iVar8 + 0x28) = pvVar9;
      *(undefined4 *)(iVar8 + 0x2c) = 2;
    }
  }
  if (*(int *)(iVar8 + 0x30) == 0) {
    *(undefined4 *)(iVar8 + 0x30) = 1;
  }
  iVar2 = *(int *)(param_1 + 0x14);
  if (**(int **)(iVar8 + 0x28) == iVar2) {
    uVar1 = *(undefined2 *)(param_1 + 4);
    local_10[0] = 0.0;
    local_10[1] = 0.0;
    local_10[2] = 0.0;
    local_10[3] = 0.0;
    for (pvVar9 = thunk_GetNavyPrimaryOrderListHead(); pvVar9 != (void *)0x0;
        pvVar9 = *(void **)((int)pvVar9 + 0x24)) {
      if ((*(int *)((int)pvVar9 + 8) == iVar2) &&
         (cVar6 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))
                            (uVar1,*(undefined2 *)((int)pvVar9 + 0x14)), cVar6 != '\0')) {
        sVar7 = thunk_GetNavyOrderNormalizationBaseByNationType();
        fVar3 = (float)((int)*(short *)((int)pvVar9 + 0x1c) / (int)sVar7);
        uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
        local_10[0] = (float)(int)(short)uVar10 * fVar3 + local_10[0];
        uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
        local_10[1] = (float)(int)(short)uVar10 * fVar3 + local_10[1];
        uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
        local_10[2] = (float)(int)(short)uVar10 * fVar3 + local_10[2];
        uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
        local_10[3] = (float)(int)(short)uVar10 + local_10[3];
      }
    }
    pfVar11 = local_10;
    iVar8 = 4;
    fVar3 = _DAT_0065a9e8;
    do {
      fVar3 = fVar3 + *pfVar11;
      pfVar11 = pfVar11 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    fVar4 = _DAT_0065a9e8;
    if (fVar3 != (float)_DAT_0065a9f0) {
      psVar12 = &DAT_00697958;
      pfVar11 = local_10;
      do {
        fVar5 = *pfVar11 / fVar3 - (float)(int)*psVar12 * (float)_DAT_0065a9f8;
        if (fVar5 <= (float)_DAT_0065a9f0) {
          fVar5 = -fVar5;
        }
        fVar4 = fVar4 + fVar5;
        psVar12 = psVar12 + 1;
        pfVar11 = pfVar11 + 1;
      } while ((int)psVar12 < 0x697960);
      fVar4 = fVar3 * ((float)_DAT_0065aa08 - fVar4 * (float)_DAT_0065aa00);
    }
    if ((float)_DAT_0065a9f0 < fVar4) {
      *(undefined1 *)(param_1 + 8) = 1;
      return;
    }
  }
  *(undefined1 *)(param_1 + 8) = 2;
  return;
}

