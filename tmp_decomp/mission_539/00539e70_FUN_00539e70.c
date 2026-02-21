
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __fastcall FUN_00539e70(int param_1)

{
  short sVar1;
  float fVar2;
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
  int iVar13;
  bool bVar14;
  float local_20;
  int *local_1c;
  float local_10 [4];
  
  local_20 = DAT_0065a9b8;
  sVar1 = *(short *)(g_pLocalizationTable + 0x2c);
  iVar13 = 7;
  local_1c = &DAT_006a429c;
  fVar3 = (float)_DAT_0065aa28;
  do {
    iVar8 = *local_1c;
    if (iVar8 != 0) {
      if (*(short *)(iVar8 + 0xe) < 200) {
        if ((float)(int)*(short *)(&g_pDiplomacyTurnStateManager->field_0x79c +
                                  ((short)iVar13 * 0x17 + (int)*(short *)(param_1 + 4)) * 2) <=
            (float)(int)(short)((int)((int)sVar1 + ((int)sVar1 >> 0x1f & 3U)) >> 2) - fVar3) {
          bVar14 = false;
        }
        else {
          bVar14 = true;
        }
      }
      else {
        sVar7 = *(short *)(iVar8 + 0xe);
        if (sVar7 < 200) {
          if (sVar7 < 100) {
            bVar14 = *(short *)(iVar8 + 0xc) == *(short *)(param_1 + 4);
          }
          else {
            bVar14 = (short)(sVar7 + -100) == *(short *)(param_1 + 4);
          }
        }
        else {
          bVar14 = (short)(sVar7 + -200) == *(short *)(param_1 + 4);
        }
      }
      if (bVar14) {
        iVar8 = FindFirstPortZoneContextByNation(iVar13);
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
        local_10[0] = 0.0;
        iVar8 = **(int **)(iVar8 + 0x28);
        local_10[1] = 0.0;
        local_10[2] = 0.0;
        local_10[3] = 0.0;
        for (pvVar9 = thunk_GetNavyPrimaryOrderListHead(); pvVar9 != (void *)0x0;
            pvVar9 = *(void **)((int)pvVar9 + 0x24)) {
          if ((*(int *)((int)pvVar9 + 8) == iVar8) &&
             (cVar6 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))
                                (*(undefined2 *)(param_1 + 4),*(undefined2 *)((int)pvVar9 + 0x14)),
             cVar6 != '\0')) {
            sVar7 = thunk_GetNavyOrderNormalizationBaseByNationType();
            fVar2 = (float)((int)*(short *)((int)pvVar9 + 0x1c) / (int)sVar7);
            uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
            local_10[0] = (float)(int)(short)uVar10 * fVar2 + local_10[0];
            uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
            local_10[1] = (float)(int)(short)uVar10 * fVar2 + local_10[1];
            uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
            local_10[2] = (float)(int)(short)uVar10 * fVar2 + local_10[2];
            uVar10 = thunk_ComputeNavyOrderPriorityContributionPercentByCategory();
            local_10[3] = (float)(int)(short)uVar10 + local_10[3];
          }
        }
        pfVar11 = local_10;
        iVar8 = 4;
        fVar2 = _DAT_0065a9e8;
        do {
          fVar2 = fVar2 + *pfVar11;
          pfVar11 = pfVar11 + 1;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        fVar4 = _DAT_0065a9e8;
        if (fVar2 != (float)_DAT_0065a9f0) {
          psVar12 = &DAT_00697960;
          pfVar11 = local_10;
          do {
            fVar5 = *pfVar11 / fVar2 - (float)(int)*psVar12 * (float)_DAT_0065a9f8;
            if (fVar5 <= (float)_DAT_0065a9f0) {
              fVar5 = -fVar5;
            }
            fVar4 = fVar4 + fVar5;
            psVar12 = psVar12 + 1;
            pfVar11 = pfVar11 + 1;
          } while ((int)psVar12 < 0x697968);
          fVar4 = fVar2 * ((float)_DAT_0065aa08 - fVar4 * (float)_DAT_0065aa00);
        }
        local_20 = fVar4 + local_20;
      }
    }
    local_1c = local_1c + 1;
    iVar13 = iVar13 + 1;
  } while ((int)local_1c < 0x6a42dc);
  psVar12 = &DAT_00697978;
  pfVar11 = (float *)(param_1 + 0x2c);
  do {
    sVar1 = *psVar12;
    psVar12 = psVar12 + 1;
    *pfVar11 = (float)(int)sVar1 * local_20 * (float)_DAT_0065a9f8;
    pfVar11 = pfVar11 + 1;
  } while ((int)psVar12 < 0x697980);
  return;
}

