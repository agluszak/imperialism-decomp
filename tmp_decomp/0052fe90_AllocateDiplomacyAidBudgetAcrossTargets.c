
/* Allocates diplomacy aid budget in tiered chunks (1000,3000,5000,10000) across targets ordered by
   compatibility matrix class (2, then 1, then fallback handling). */

void __fastcall AllocateDiplomacyAidBudgetAcrossTargets(int param_1)

{
  short sVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  short *psVar5;
  undefined2 extraout_var;
  int iVar6;
  int iVar7;
  undefined4 *unaff_FS_OFFSET;
  int *local_18;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0063411a;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  iVar3 = __ftol();
  if (1000 < iVar3) {
    iVar4 = AllocateWithFallbackHandler(0x18);
    local_4 = 0;
    if (iVar4 == 0) {
      local_18 = (int *)0x0;
    }
    else {
      local_18 = (int *)thunk_FUN_004ee540();
    }
    local_4 = 0xffffffff;
    thunk_FUN_004ee5c0();
    (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x88))
              (CONCAT22((short)((uint)*(int *)(param_1 + 4) >> 0x10),
                        *(undefined2 *)(*(int *)(param_1 + 4) + 0xc)),0,local_18);
    iVar4 = local_18[2];
    do {
      if ((short)iVar4 < 1) break;
      psVar5 = (short *)(**(code **)(*local_18 + 0x2c))((int)(short)iVar4);
      sVar2 = *psVar5;
      if (psVar5[1] < 0xff) {
        sVar1 = LookupOrderCompatibilityMatrixValue
                          (g_pDiplomacyTurnStateManager,*(short *)(*(int *)(param_1 + 4) + 0xc),
                           sVar2);
        if (sVar1 == 2) {
          if (iVar3 < 3000) {
            iVar7 = 1000;
          }
          else if (iVar3 < 5000) {
            iVar7 = 3000;
          }
          else {
            iVar7 = ((9999 < iVar3) - 1 & 0xffffec78) + 10000;
          }
          iVar3 = iVar3 - (short)iVar7;
          (**(code **)(**(int **)(param_1 + 4) + 0x1d4))(CONCAT22(extraout_var,sVar2),iVar7);
          psVar5 = (short *)(param_1 + 0x50 + sVar2 * 2);
          *psVar5 = *psVar5 + (short)iVar7;
        }
      }
      iVar4 = iVar4 + -1;
    } while (1000 < iVar3);
    if (1000 < iVar3) {
      iVar7 = local_18[2];
      do {
        if ((short)iVar7 < 1) break;
        psVar5 = (short *)(**(code **)(*local_18 + 0x2c))((int)(short)iVar7);
        sVar2 = *psVar5;
        iVar4 = (int)sVar2;
        sVar1 = LookupOrderCompatibilityMatrixValue
                          (g_pDiplomacyTurnStateManager,*(short *)(*(int *)(param_1 + 4) + 0xc),
                           sVar2);
        if (sVar1 == 1) {
          if (iVar3 < 3000) {
            iVar6 = 1000;
          }
          else if (iVar3 < 5000) {
            iVar6 = 3000;
          }
          else {
            iVar6 = ((9999 < iVar3) - 1 & 0xffffec78) + 10000;
          }
          iVar3 = iVar3 - (short)iVar6;
          (**(code **)(**(int **)(param_1 + 4) + 0x1d4))(sVar2,iVar6);
          psVar5 = (short *)(param_1 + 0x50 + iVar4 * 2);
          *psVar5 = *psVar5 + (short)iVar6;
          if (4999 < *(short *)(param_1 + 0x50 + iVar4 * 2)) {
            SetNationPairSpecialRelationFlagAndQueueEvent14Or16
                      (g_pDiplomacyTurnStateManager,2,(int)*(short *)(*(int *)(param_1 + 4) + 0xc),
                       iVar4);
          }
        }
        iVar7 = iVar7 + -1;
      } while (1000 < iVar3);
      if (1000 < iVar3) {
        iVar7 = local_18[2];
        do {
          if ((short)iVar7 < 1) break;
          psVar5 = (short *)(**(code **)(*local_18 + 0x2c))((int)(short)iVar7);
          iVar4 = CONCAT22((short)((uint)iVar4 >> 0x10),*psVar5);
          if ((psVar5[1] < 0xff) &&
             (sVar2 = LookupOrderCompatibilityMatrixValue
                                (g_pDiplomacyTurnStateManager,
                                 *(short *)(*(int *)(param_1 + 4) + 0xc),*psVar5), sVar2 == 0)) {
            (**(code **)(**(int **)(param_1 + 4) + 0x1d0))(iVar4,0x133);
            iVar3 = 0;
          }
          iVar7 = iVar7 + -1;
        } while (1000 < iVar3);
      }
    }
    if (local_18 != (int *)0x0) {
      (**(code **)(*local_18 + 0x24))();
    }
  }
  *unaff_FS_OFFSET = local_c;
  return;
}

