
undefined4 __thiscall
FUN_00557f10(int param_1,undefined2 *param_2,int param_3,undefined4 param_4,short param_5)

{
  uint uVar1;
  bool bVar2;
  bool bVar3;
  undefined1 uVar4;
  char cVar5;
  bool bVar6;
  short sVar7;
  short sVar8;
  short sVar9;
  int *piVar10;
  undefined1 *puVar11;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  int iVar15;
  short sVar16;
  short sVar17;
  int iVar18;
  short sVar19;
  int iVar20;
  int iVar21;
  int *piVar22;
  undefined4 *unaff_FS_OFFSET;
  bool bVar23;
  short sStack_29c;
  int *local_298;
  int *piStack_284;
  int aiStack_280 [3];
  undefined1 auStack_274 [2];
  undefined1 uStack_272;
  undefined1 uStack_271;
  undefined4 uStack_270;
  int iStack_26c;
  undefined1 auStack_268 [64];
  undefined1 auStack_228 [510];
  undefined2 uStack_2a;
  undefined2 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_006353ab;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  sVar7 = thunk_GetPortZoneOwnerNationCodeFromMissionField48();
  sVar16 = (short)param_4;
  iVar15 = (int)(short)(*(short *)((&g_apNationStates)[sVar16] + 0xa4) -
                       *(short *)((&g_apNationStates)[sVar16] + 0xa2));
  if (iVar15 == 0) {
    sVar9 = 0;
  }
  else {
    sVar9 = (short)((param_5 * 100) / iVar15);
  }
  local_298 = *(int **)(param_1 + 4);
  if (local_298 != (int *)0x0) {
    do {
      if (((short)local_298[7] == sVar16) && (local_298[2] == 7)) break;
      local_298 = (int *)local_298[0xb];
    } while (local_298 != (int *)0x0);
    if (local_298 != (int *)0x0) {
      for (piVar22 = (int *)local_298[4]; piVar22 != (int *)0x0; piVar22 = (int *)piVar22[1]) {
        if ((*(short *)(*piVar22 + 0x1c) <
             *(short *)(&DAT_00698114 + *(short *)(*piVar22 + 4) * 0x24)) ||
           (iVar15 = GenerateThreadLocalRandom15(), (int)sVar9 <= iVar15 % 100)) {
          uVar4 = 0;
        }
        else {
          uVar4 = 1;
        }
        *(undefined1 *)(piVar22 + 3) = uVar4;
      }
    }
  }
  piVar22 = *(int **)(param_1 + 4);
  if (piVar22 != (int *)0x0) {
LAB_0055802d:
    if (*(char *)((int)piVar22 + 0x26) == '\0') {
      if (piVar22 == (int *)0x0) {
        sVar9 = 0;
      }
      else {
        sVar9 = 0;
        for (iVar15 = piVar22[4]; iVar15 != 0; iVar15 = *(int *)(iVar15 + 4)) {
          sVar9 = sVar9 + 1;
        }
      }
      if (0 < sVar9) {
        if (((short)piVar22[2] != 6) || (bVar23 = true, piVar22[3] != param_3)) {
          bVar23 = false;
        }
        if ((short)piVar22[2] == 3) {
          iVar15 = piVar22[6];
          piVar10 = (int *)thunk_EnsureDwordPointerArraySlotAndReturnPointer(0);
          bVar3 = true;
          if (iVar15 != *piVar10) goto LAB_00558093;
        }
        else {
LAB_00558093:
          bVar3 = false;
        }
        if (((short)piVar22[7] == sVar16) ||
           (cVar5 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))
                              ((short)piVar22[7],param_4), cVar5 == '\0')) {
          bVar2 = false;
        }
        else {
          bVar2 = true;
        }
        if (((sVar7 < 7) ||
            (cVar5 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))
                               ((short)piVar22[7],(int)sVar7), cVar5 == '\0')) ||
           ((short)piVar22[2] != 6)) {
          bVar6 = false;
        }
        else {
          bVar6 = true;
        }
        if (((bVar23) || (bVar3)) && ((bVar2 || (bVar6)))) {
          iVar20 = piVar22[2];
          iVar15 = 0;
          iVar18 = 0;
          for (piVar10 = (int *)piVar22[4]; piVar10 != (int *)0x0; piVar10 = (int *)piVar10[1]) {
            if ((char)piVar10[3] != '\0') {
              iVar15 = iVar15 + *(short *)(&DAT_00698124 + *(short *)(*piVar10 + 4) * 0x24);
              iVar18 = iVar18 + 1;
            }
          }
          if (iVar18 == 0) {
            sVar9 = 0;
          }
          else {
            sVar9 = (short)((iVar15 * 10) / iVar18);
          }
          sVar8 = thunk_FUN_004b4290();
          sStack_29c = thunk_FUN_004b4310();
          if (0 < sStack_29c) {
            sStack_29c = param_5 / sStack_29c;
          }
          if (local_298 == (int *)0x0) {
            sVar19 = 0;
          }
          else {
            sVar19 = 0;
            for (iVar15 = local_298[4]; iVar15 != 0; iVar15 = *(int *)(iVar15 + 4)) {
              if (*(char *)(iVar15 + 0xc) != '\0') {
                sVar19 = sVar19 + 1;
              }
            }
          }
          if (piVar22 == (int *)0x0) {
            sVar17 = 0;
          }
          else {
            sVar17 = 0;
            for (iVar15 = piVar22[4]; iVar15 != 0; iVar15 = *(int *)(iVar15 + 4)) {
              sVar17 = sVar17 + 1;
            }
          }
          iVar15 = GenerateThreadLocalRandom15();
          iVar15 = iVar15 % 100;
          if (iVar15 < (short)(sVar17 + sVar19 +
                               (-(ushort)((short)iVar20 != 6) & 0xffe2) + (sVar9 - sVar8) + 0x28 +
                              sStack_29c)) {
            if ((local_298 == (int *)0x0) ||
               (iVar15 = (int)(short)local_298[9],
               (int)*(short *)((int)local_298 + 0x1e) + (int)*(short *)((int)local_298 + 0x22) +
               (int)(short)local_298[8] + iVar15 == 0)) {
              bVar23 = true;
            }
            else {
              bVar23 = false;
            }
            if ((!bVar23) && (iVar18 = local_298[4], iVar18 != 0)) {
LAB_00558249:
              if (*(char *)(iVar18 + 0xc) == '\0') goto code_r0x00558250;
              cVar5 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))
                                (param_4,CONCAT22((short)((uint)iVar15 >> 0x10),(short)piVar22[7]));
              if (cVar5 == '\0') {
                iVar15 = 0;
                for (piVar10 = (int *)local_298[4]; piVar10 != (int *)0x0;
                    piVar10 = (int *)piVar10[1]) {
                  iVar21 = *piVar10;
                  iVar12 = (int)*(short *)(iVar21 + 4);
                  sVar9 = *(short *)(iVar21 + 0x30);
                  iVar20 = (int)(short)((sVar9 / 100 + (sVar9 >> 0xf)) -
                                       (short)((longlong)(int)sVar9 * 0x51eb851f >> 0x3f));
                  iVar18 = iVar20 + 5 + (&DAT_00698118)[iVar12 * 9] * 10;
                  iVar20 = iVar20 + 5 + (&DAT_00698108)[iVar12 * 9] * 10;
                  iVar15 = iVar15 + ((int)(short)(((short)(iVar20 / 10) + (short)(iVar20 >> 0x1f)) -
                                                 (short)((longlong)iVar20 * 0x66666667 >> 0x3f)) +
                                     ((int)(short)(((short)(iVar18 / 10) + (short)(iVar18 >> 0x1f))
                                                  - (short)((longlong)iVar18 * 0x66666667 >> 0x3f))
                                     + (int)*(short *)(&DAT_0069810c + iVar12 * 9)) * 100 +
                                    (int)*(short *)(iVar21 + 0x1c)) /
                                    (int)*(short *)(&DAT_00698110 + iVar12 * 0x24);
                }
                iVar18 = 0;
                for (piVar10 = (int *)piVar22[4]; piVar10 != (int *)0x0; piVar10 = (int *)piVar10[1]
                    ) {
                  iVar12 = *piVar10;
                  iVar13 = (int)*(short *)(iVar12 + 4);
                  sVar9 = *(short *)(iVar12 + 0x30);
                  iVar21 = (int)(short)((sVar9 / 100 + (sVar9 >> 0xf)) -
                                       (short)((longlong)(int)sVar9 * 0x51eb851f >> 0x3f));
                  iVar20 = iVar21 + 5 + (&DAT_00698118)[iVar13 * 9] * 10;
                  iVar21 = iVar21 + 5 + (&DAT_00698108)[iVar13 * 9] * 10;
                  iVar18 = iVar18 + ((int)(short)(((short)(iVar21 / 10) + (short)(iVar21 >> 0x1f)) -
                                                 (short)((longlong)iVar21 * 0x66666667 >> 0x3f)) +
                                     ((int)(short)(((short)(iVar20 / 10) + (short)(iVar20 >> 0x1f))
                                                  - (short)((longlong)iVar20 * 0x66666667 >> 0x3f))
                                     + (int)*(short *)(&DAT_0069810c + iVar13 * 9)) * 100 +
                                    (int)*(short *)(iVar12 + 0x1c)) /
                                    (int)*(short *)(&DAT_00698110 + iVar13 * 0x24);
                }
                bVar23 = iVar15 * 3 < iVar18;
              }
              else {
                iVar15 = piVar22[4];
                sVar9 = 0;
                aiStack_280[0] = 200;
                aiStack_280[1] = 100;
                aiStack_280[2] = 0x32;
                for (; iVar15 != 0; iVar15 = *(int *)(iVar15 + 4)) {
                  sVar8 = thunk_FUN_00550aa0();
                  sVar9 = sVar9 + sVar8;
                }
                sVar8 = thunk_ComputeTaskForceOrderAggregateScore();
                if (sVar9 * 100 < aiStack_280[piVar22[1]] * (int)sVar8) {
                  bVar23 = false;
                  puVar11 = auStack_268;
                  iVar15 = 2;
                  do {
                    *puVar11 = 0;
                    puVar11 = puVar11 + 0x20;
                    iVar15 = iVar15 + -1;
                  } while (iVar15 != 0);
                  thunk_FUN_00412600(auStack_228,0xff,2,&LAB_0040722a);
                  uStack_28 = 0;
                  uStack_2a = 0;
                  uStack_20 = 0;
                  uStack_24 = 0;
                  iStack_26c = piVar22[6];
                  uStack_4 = 0;
                  uStack_270 = 1;
                  uStack_271 = 0;
                  uStack_272 = 1;
                  thunk_BuildMapOrderBattleSideSnapshot((int)auStack_274,0,(int)piVar22);
                  thunk_BuildMapOrderBattleSideSnapshot((int)auStack_274,1,(int)local_298);
                  thunk_RefreshMapOrderBattleSideSnapshot((int)auStack_274,0,(int)piVar22);
                  thunk_RefreshMapOrderBattleSideSnapshot((int)auStack_274,1,(int)local_298);
                  thunk_FUN_004a6e80(auStack_274,0);
                  uStack_4 = 0xffffffff;
                  FreeHeapBufferIfNotNull(uStack_24);
                  FreeHeapBufferIfNotNull(uStack_20);
                }
                else {
                  if (piVar22 == (int *)0x0) {
                    sVar9 = 0;
                  }
                  else {
                    sVar9 = 0;
                    for (iVar15 = piVar22[4]; iVar15 != 0; iVar15 = *(int *)(iVar15 + 4)) {
                      sVar9 = sVar9 + 1;
                    }
                  }
                  if (((sVar9 != 0) && (sVar9 = thunk_GetMapOrderEntryChildCount(), sVar9 != 0)) &&
                     ((*(short *)(g_pLocalizationTable + 0x4a) == 0 ||
                      ((iVar15 = piVar22[7], sVar9 = thunk_GetActiveNationId(),
                       sVar9 != (short)iVar15 &&
                       (iVar15 = local_298[7], sVar9 = thunk_GetActiveNationId(),
                       sVar9 != (short)iVar15)))))) {
                    thunk_ResolveMapOrderPairConflictStep(piVar22,local_298);
                    piStack_284 = (int *)0x0;
                  }
                  bVar23 = piStack_284 == piVar22;
                }
              }
              goto LAB_005585bf;
            }
LAB_00558257:
            bVar23 = true;
LAB_005585bf:
            if (bVar23) {
              uVar1 = *(uint *)(param_2 + 2);
              *param_2 = (short)piVar22[7];
              *(int **)(param_2 + 4) = piVar22;
              *(uint *)(param_2 + 2) = uVar1 & 0xfffffffc;
              cVar5 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))
                                (param_4,CONCAT22((short)((uVar1 & 0xfffffffc) >> 0x10),
                                                  (short)piVar22[7]));
              if (cVar5 == '\0') goto LAB_00558676;
              iVar15 = GenerateThreadLocalRandom15();
              if (piVar22 == (int *)0x0) {
                sVar7 = 0;
              }
              else {
                sVar7 = 0;
                for (iVar18 = piVar22[4]; iVar18 != 0; iVar18 = *(int *)(iVar18 + 4)) {
                  sVar7 = sVar7 + 1;
                }
              }
              sVar16 = (short)(iVar15 % 100);
              if ((short)(sVar7 + 10) <= sVar16) {
                if ((int)sVar16 < (short)(sVar7 + 10) * 2) {
                  *(uint *)(param_2 + 2) = *(uint *)(param_2 + 2) | 1;
                }
LAB_00558676:
                uVar14 = 1;
                goto LAB_005585d5;
              }
              *(uint *)(param_2 + 2) = *(uint *)(param_2 + 2) | 2;
              uVar14 = 1;
              goto LAB_005585d5;
            }
          }
        }
      }
    }
    piVar22 = (int *)piVar22[0xb];
    if (piVar22 == (int *)0x0) goto LAB_005585d3;
    goto LAB_0055802d;
  }
LAB_005585d3:
  uVar14 = 0;
LAB_005585d5:
  *unaff_FS_OFFSET = local_c;
  return uVar14;
code_r0x00558250:
  iVar18 = *(int *)(iVar18 + 4);
  if (iVar18 == 0) goto LAB_00558257;
  goto LAB_00558249;
}

