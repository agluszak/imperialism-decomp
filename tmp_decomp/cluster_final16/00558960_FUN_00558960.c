
void __thiscall FUN_00558960(undefined4 param_1,short param_2)

{
  short *psVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  char cVar5;
  short sVar6;
  undefined4 uVar7;
  char *pcVar8;
  int *piVar9;
  undefined2 *puVar10;
  int iVar11;
  undefined1 *puVar12;
  int iVar13;
  undefined2 extraout_var;
  bool bVar14;
  short sVar15;
  short sVar16;
  int iVar17;
  int iVar18;
  undefined4 *puVar19;
  short *psVar20;
  undefined4 *unaff_FS_OFFSET;
  bool bVar21;
  int iStack_320;
  undefined4 uStack_31c;
  int local_318;
  undefined1 auStack_314 [4];
  undefined4 uStack_310;
  undefined4 uStack_30c;
  int iStack_308;
  undefined1 auStack_304 [4];
  short asStack_300 [2];
  uint uStack_2fc;
  int iStack_2f8;
  int iStack_2f4;
  undefined1 auStack_2f0 [4];
  int local_2ec;
  char *pcStack_2e8;
  int iStack_2e4;
  int iStack_2e0;
  int iStack_2dc;
  undefined1 auStack_2d8 [4];
  int local_2d4;
  int iStack_2d0;
  undefined1 auStack_2cc [4];
  int iStack_2c8;
  int iStack_2c4;
  undefined1 auStack_2c0 [4];
  undefined1 auStack_2bc [4];
  undefined1 auStack_2b8 [4];
  undefined1 auStack_2b4 [4];
  undefined4 local_2b0;
  int iStack_2ac;
  undefined1 auStack_2a8 [4];
  int iStack_2a4;
  undefined1 auStack_2a0 [4];
  int iStack_29c;
  undefined1 auStack_298 [4];
  undefined1 auStack_294 [4];
  short sStack_290;
  undefined4 auStack_28e [6];
  undefined1 uStack_274;
  undefined1 uStack_273;
  undefined1 uStack_272;
  undefined1 uStack_271;
  undefined4 uStack_270;
  undefined4 uStack_26c;
  char acStack_268 [32];
  char acStack_248 [32];
  char acStack_228 [255];
  char acStack_129 [255];
  short sStack_2a;
  short sStack_28;
  int iStack_24;
  undefined2 *puStack_20;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  int iStack_4;
  
  iStack_4 = 0xffffffff;
  puStack_8 = &LAB_0063547b;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  local_2d4 = 0;
  local_2b0 = param_1;
  do {
    iVar17 = (int)(short)local_2d4;
    iVar18 = iVar17 * 4;
    iVar13 = local_2d4;
    if ((&g_pTerrainTypeDescriptorTable)[iVar17] != 0) {
      if ((&g_apNationStates)[iVar17] == 0) {
        iVar17 = 0;
      }
      else {
        iVar17 = *(int *)((&g_apNationStates)[iVar17] + 0x894);
      }
      if (iVar17 != 0) {
        local_318 = 0;
        local_2ec = iVar18;
        do {
          iVar17 = local_318;
          sVar6 = (**(code **)(**(int **)((int)&g_apNationStates + iVar18) + 0x1b4))(local_318);
          iStack_2a4 = (int)sVar6;
          iStack_2dc = 1;
          if (0 < iStack_2a4) {
            do {
              (**(code **)(**(int **)((int)&g_apNationStates + iVar18) + 0x1bc))
                        (iVar17,iStack_2dc,(int)&uStack_30c + 2,&uStack_31c,&iStack_2e0,&iStack_2f4)
              ;
              if ((short)uStack_31c != 0) {
                iStack_308 = iVar13;
                if (uStack_30c._2_2_ != 1) {
                  iStack_308 = iStack_2e0;
                }
                iStack_2d0 = iStack_2e0;
                if (uStack_30c._2_2_ != 1) {
                  iStack_2d0 = iVar13;
                }
                iVar18 = iStack_2e0;
                if (param_2 == 1) {
                  iVar18 = iVar13;
                }
                uVar7 = FindFirstPortZoneContextByNation(iVar18);
                cVar5 = thunk_FUN_00557f10(asStack_300,uVar7,iVar13,uStack_31c);
                if (cVar5 != '\0') {
                  pcVar8 = acStack_268;
                  iVar18 = 2;
                  do {
                    *pcVar8 = '\0';
                    pcVar8 = pcVar8 + 0x20;
                    iVar18 = iVar18 + -1;
                  } while (iVar18 != 0);
                  thunk_FUN_00412600(acStack_228,0xff,2,&LAB_0040722a);
                  sStack_28 = 0;
                  sStack_2a = 0;
                  puStack_20 = (undefined2 *)0x0;
                  iStack_24 = 0;
                  uStack_274 = (undefined1)asStack_300[0];
                  uStack_273 = (undefined1)iVar13;
                  uStack_272 = 0;
                  uStack_271 = 0;
                  uStack_270 = 2;
                  uStack_26c = *(undefined4 *)(iStack_2f8 + 0x18);
                  iStack_4 = 0;
                  InitializeSharedStringRefFromEmpty();
                  iStack_4._0_1_ = 1;
                  FormatOverlayTerrainLabelText(&iStack_320);
                  iVar13 = 0;
                  do {
                    cVar5 = (acStack_268 + iVar13)[iStack_320 - (int)acStack_268];
                    acStack_268[iVar13] = cVar5;
                    if (cVar5 == '\0') break;
                    iVar13 = iVar13 + 1;
                  } while (iVar13 < 0x20);
                  FormatOverlayTerrainLabelText(&iStack_320);
                  iVar13 = 0;
                  do {
                    cVar5 = (acStack_248 + iVar13)[iStack_320 - (int)acStack_248];
                    acStack_248[iVar13] = cVar5;
                    if (cVar5 == '\0') break;
                    iVar13 = iVar13 + 1;
                  } while (iVar13 < 0x20);
                  thunk_BuildTaskForceSelectionOverlayLabelText(&iStack_320);
                  iVar13 = 0;
                  do {
                    cVar5 = (acStack_228 + iVar13)[iStack_320 - (int)acStack_228];
                    acStack_228[iVar13] = cVar5;
                    if (cVar5 == '\0') break;
                    iVar13 = iVar13 + 1;
                  } while (iVar13 < 0xff);
                  FormatOverlayTerrainLabelText(&iStack_320);
                  InitializeSharedStringRefFromEmpty();
                  iStack_4._0_1_ = 2;
                  InitializeSharedStringRefFromEmpty();
                  iStack_4._0_1_ = 3;
                  InitializeSharedStringRefFromEmpty();
                  iStack_4._0_1_ = 4;
                  InitializeSharedStringRefFromEmpty();
                  iStack_4._0_1_ = 5;
                  FormatStringWithVarArgsToSharedRef
                            (auStack_2f0,&g_szDecimalFormat,(int)(short)uStack_31c);
                  (**(code **)(*g_pLocalizationTable + 0x7c))(iVar17,auStack_314);
                  (**(code **)(*g_pLocalizationTable + 0x84))(0x273c,0,auStack_2f0);
                  scanBracketExpressions(g_pLocalizationTable,&iStack_2e4,pcStack_2e8);
                  iVar13 = 0;
                  do {
                    cVar5 = (acStack_129 + iVar13)[iStack_2e4 - (int)acStack_129];
                    acStack_129[iVar13] = cVar5;
                    if (cVar5 == '\0') break;
                    iVar13 = iVar13 + 1;
                  } while (iVar13 < 0xff);
                  bVar21 = param_2 == 1;
                  if ((param_2 == 1) && (uStack_30c._2_2_ == 1)) {
                    bVar2 = true;
                  }
                  else {
                    bVar2 = false;
                  }
                  if ((param_2 == 2) && (uStack_30c._2_2_ == 0)) {
                    bVar3 = true;
                  }
                  else {
                    bVar3 = false;
                  }
                  if ((bVar2) || (bVar3)) {
                    bVar14 = false;
                  }
                  else {
                    bVar14 = true;
                  }
                  bVar4 = false;
                  iVar13 = (int)(short)uStack_31c;
                  if ((uStack_2fc & 3) == 0) {
                    if ((bVar21) || (!bVar3)) goto LAB_005592b9;
                    iStack_4._0_1_ = 4;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4._0_1_ = 3;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4._0_1_ = 2;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4._0_1_ = 1;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4 = (uint)iStack_4._1_3_ << 8;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4 = 0xffffffff;
                    FreeHeapBufferIfNotNull(iStack_24);
                  }
                  else {
                    sStack_290 = 0;
                    puVar19 = auStack_28e;
                    for (iVar18 = 6; iVar18 != 0; iVar18 = iVar18 + -1) {
                      *puVar19 = 0;
                      puVar19 = puVar19 + 1;
                    }
                    *(undefined2 *)puVar19 = 0;
                    iStack_2c4 = thunk_FUN_004b4390(uStack_31c,&sStack_290);
                    sVar6 = (short)iStack_2c4;
                    if (sVar6 != 0) {
                      iVar18 = (int)sVar6;
                      iStack_2ac = iVar18 * 3 + iVar13;
                      iStack_29c = iVar18;
                      if (bVar14) {
                        if ((short)iStack_308 < 7) {
                          thunk_FUN_004ddcf0(local_318,-iStack_2c4);
                        }
                        bVar4 = true;
                      }
                      sStack_28 = sVar6 + 1;
                      if ((bVar14) && ((uStack_2fc & 2) != 0)) {
                        sStack_28 = sVar6 + 2;
                      }
                      iVar13 = (int)sStack_28;
                      puStack_20 = (undefined2 *)AllocateWithFallbackHandler(iVar13 * 0x2c);
                      if (puStack_20 == (undefined2 *)0x0) {
                        puStack_20 = (undefined2 *)0x0;
                      }
                      else if (-1 < iVar13 + -1) {
                        puVar10 = puStack_20 + 2;
                        do {
                          *(undefined1 *)puVar10 = 0;
                          puVar10 = puVar10 + 0x16;
                          iVar13 = iVar13 + -1;
                        } while (iVar13 != 0);
                      }
                      InitializeSharedStringRefFromEmpty();
                      iStack_4 = CONCAT31(iStack_4._1_3_,6);
                      iVar13 = 1;
                      iVar17 = 0;
                      psVar20 = &sStack_290;
                      do {
                        if (*psVar20 != 0) {
                          iVar18 = CompareAnsiStringsWithMbcsAwareness(uStack_310,PTR_DAT_0065c2a8);
                          if (iVar18 != 0) {
                            AssignStringSharedFromCStr(&DAT_00695760);
                          }
                          InitializeSharedStringRefFromEmpty();
                          iStack_4._0_1_ = 7;
                          thunk_FUN_00550c20(auStack_2cc,iVar17,CONCAT22(extraout_var,*psVar20));
                          AssignStringSharedFromRef(auStack_2cc);
                          iVar18 = 0;
                          if (0 < *psVar20) {
                            iVar11 = iVar13 * 0x2c;
                            do {
                              *(short *)((int)puStack_20 + iVar11) = (short)iVar17;
                              *(undefined4 *)((int)puStack_20 + iVar11 + 0x28) = 0x6d657263;
                              *(ushort *)((int)puStack_20 + iVar11 + 2) =
                                   (ushort)((byte)(uStack_2fc >> 1) & 1);
                              iVar13 = iVar13 + 1;
                              iVar11 = iVar11 + 0x2c;
                              iVar18 = iVar18 + 1;
                            } while (iVar18 < *psVar20);
                          }
                          iStack_4 = CONCAT31(iStack_4._1_3_,6);
                          ReleaseSharedStringRefIfNotEmpty();
                          iVar18 = iStack_29c;
                        }
                        iVar17 = iVar17 + 1;
                        psVar20 = psVar20 + 1;
                      } while (iVar17 < 0xe);
                      InitializeSharedStringRefFromEmpty();
                      iStack_4._0_1_ = 8;
                      (**(code **)(*g_pLocalizationTable + 0x84))
                                (0x273c,2 - (uint)((uStack_2fc >> 1 & 1) != 0),auStack_304);
                      uVar7 = AssignSharedStringConcatCStrAndRef
                                        (auStack_2c0,&DAT_00695880,auStack_304);
                      iStack_4._0_1_ = 9;
                      uVar7 = AssignSharedStringConcatRefAndCStr(auStack_2a0,uVar7,&DAT_00695794);
                      iStack_4._0_1_ = 10;
                      piVar9 = (int *)AssignSharedStringConcatRefAndRef
                                                (auStack_2b8,uVar7,&uStack_310);
                      iVar17 = 0;
                      do {
                        if (acStack_129[iVar17] == '\0') break;
                        iVar17 = iVar17 + 1;
                      } while (iVar17 < 0xff);
                      if (iVar17 < 0xff) {
                        iVar11 = *piVar9 - iVar17;
                        do {
                          cVar5 = *(char *)(iVar11 + iVar17);
                          acStack_129[iVar17] = cVar5;
                          if (cVar5 == '\0') break;
                          iVar17 = iVar17 + 1;
                        } while (iVar17 < 0xff);
                      }
                      ReleaseSharedStringRefIfNotEmpty();
                      iStack_4._0_1_ = 9;
                      ReleaseSharedStringRefIfNotEmpty();
                      iStack_4._0_1_ = 8;
                      ReleaseSharedStringRefIfNotEmpty();
                      iVar17 = local_318;
                      if (((uStack_2fc & 2) != 0) && (bVar14)) {
                        FormatStringWithVarArgsToSharedRef(auStack_304,&g_szDecimalFormat,iVar18);
                        iVar17 = local_318;
                        (**(code **)(*g_pLocalizationTable + 0x7c))(local_318,auStack_314);
                        InitializeSharedStringRefFromEmpty();
                        uStack_c = CONCAT31(uStack_c._1_3_,0xb);
                        (**(code **)(*g_pLocalizationTable + 0x84))(0x273c,3,&iStack_2e0);
                        uVar7 = AssignSharedStringConcatCStrAndRef
                                          (auStack_2b4,&DAT_00695880,auStack_2d8);
                        iStack_4._0_1_ = 0xc;
                        uVar7 = AssignSharedStringConcatRefAndCStr(auStack_2bc,uVar7,&DAT_00695794);
                        iStack_4._0_1_ = 0xd;
                        uVar7 = AssignSharedStringConcatRefAndRef(auStack_298,uVar7,auStack_304);
                        iStack_4._0_1_ = 0xe;
                        uVar7 = AssignSharedStringConcatRefAndCStr(auStack_2a8,uVar7,&DAT_00695794);
                        iStack_4._0_1_ = 0xf;
                        piVar9 = (int *)AssignSharedStringConcatRefAndRef
                                                  (auStack_294,uVar7,auStack_314);
                        iVar18 = 0;
                        do {
                          if (acStack_129[iVar18] == '\0') break;
                          iVar18 = iVar18 + 1;
                        } while (iVar18 < 0xff);
                        if (iVar18 < 0xff) {
                          iVar11 = *piVar9 - iVar18;
                          do {
                            cVar5 = *(char *)(iVar11 + iVar18);
                            acStack_129[iVar18] = cVar5;
                            if (cVar5 == '\0') break;
                            iVar18 = iVar18 + 1;
                          } while (iVar18 < 0xff);
                        }
                        ReleaseSharedStringRefIfNotEmpty();
                        iStack_4._0_1_ = 0xe;
                        ReleaseSharedStringRefIfNotEmpty();
                        iStack_4._0_1_ = 0xd;
                        ReleaseSharedStringRefIfNotEmpty();
                        iStack_4._0_1_ = 0xc;
                        ReleaseSharedStringRefIfNotEmpty();
                        iStack_4._0_1_ = 0xb;
                        ReleaseSharedStringRefIfNotEmpty();
                        iStack_4._0_1_ = 8;
                        puVar10 = puStack_20 + iVar13 * 0x16;
                        puVar10[1] = (undefined2)iStack_2c4;
                        *puVar10 = (short)iVar17;
                        *(undefined4 *)(puVar10 + 0x14) = 0x6974656d;
                        ReleaseSharedStringRefIfNotEmpty();
                      }
                      if ((uStack_2fc >> 1 & 1) != 0) {
                        iVar13 = 0;
                        psVar20 = &sStack_290;
                        do {
                          if (*psVar20 != 0) {
                            if ((&g_apNationStates)[asStack_300[0]] == 0) {
                              iVar18 = 0;
                            }
                            else {
                              iVar18 = *(int *)((&g_apNationStates)[asStack_300[0]] + 0x894);
                            }
                            psVar1 = (short *)(iVar18 + 0x5c + (short)iVar13 * 2);
                            *psVar1 = *psVar1 + *psVar20;
                          }
                          iVar13 = iVar13 + 1;
                          psVar20 = psVar20 + 1;
                        } while (iVar13 < 0xe);
                        if (bVar14) {
                          thunk_FUN_004ddcf0(iVar17,iStack_2c4);
                        }
                      }
                      iStack_4._0_1_ = 6;
                      ReleaseSharedStringRefIfNotEmpty();
                      iStack_4._0_1_ = 5;
                      ReleaseSharedStringRefIfNotEmpty();
                      iVar13 = iStack_2ac;
                    }
LAB_005592b9:
                    if (sStack_28 < 1) {
                      sStack_28 = 1;
                      puStack_20 = (undefined2 *)AllocateWithFallbackHandler(0x2c);
                      if (puStack_20 == (undefined2 *)0x0) {
                        puStack_20 = (undefined2 *)0x0;
                      }
                      else {
                        *(undefined1 *)(puStack_20 + 2) = 0;
                      }
                    }
                    iVar18 = iStack_2f8;
                    *puStack_20 = (undefined2)local_318;
                    puStack_20[1] = (short)uStack_31c;
                    puStack_20[0x12] = (undefined2)iStack_2e0;
                    *(undefined4 *)(puStack_20 + 0x14) = 0x72757074;
                    if (iStack_2f8 == 0) {
                      sVar6 = 0;
                    }
                    else {
                      sVar6 = 0;
                      for (iVar17 = *(int *)(iStack_2f8 + 0x10); iVar17 != 0;
                          iVar17 = *(int *)(iVar17 + 4)) {
                        sVar6 = sVar6 + 1;
                      }
                    }
                    if ((iStack_2f8 == 0) || (*(int *)(iStack_2f8 + 0x14) == 0)) {
                      iVar17 = 0;
                    }
                    else {
                      iVar17 = *(int *)(*(int *)(iStack_2f8 + 0x14) + 0x20);
                    }
                    if ((iVar17 != 0) &&
                       (*(short *)(iVar17 + 0x10) = *(short *)(iVar17 + 0x10) + (short)iVar13,
                       499 < *(short *)(iVar17 + 0x10))) {
                      *(undefined2 *)(iVar17 + 0x10) = 499;
                    }
                    for (piVar9 = *(int **)(iStack_2f8 + 0x10); piVar9 != (int *)0x0;
                        piVar9 = (int *)piVar9[1]) {
                      iVar17 = *piVar9;
                      *(short *)(iVar17 + 0x30) =
                           *(short *)(iVar17 + 0x30) + (short)((iVar13 * 3) / (int)sVar6);
                      if (499 < *(short *)(iVar17 + 0x30)) {
                        *(undefined2 *)(iVar17 + 0x30) = 499;
                      }
                    }
                    if ((bVar14) && (!bVar4)) {
                      bVar21 = true;
                      bVar2 = true;
                    }
                    if (iStack_2f8 == 0) {
                      sStack_2a = 0;
                    }
                    else {
                      sStack_2a = 0;
                      for (iVar13 = *(int *)(iStack_2f8 + 0x10); iVar13 != 0;
                          iVar13 = *(int *)(iVar13 + 4)) {
                        sStack_2a = sStack_2a + 1;
                      }
                    }
                    iVar13 = (int)sStack_2a;
                    iStack_24 = AllocateWithFallbackHandler(iVar13 * 0x2c);
                    if (iStack_24 == 0) {
                      iStack_24 = 0;
                    }
                    else if (-1 < iVar13 + -1) {
                      puVar12 = (undefined1 *)(iStack_24 + 4);
                      do {
                        *puVar12 = 0;
                        puVar12 = puVar12 + 0x2c;
                        iVar13 = iVar13 + -1;
                      } while (iVar13 != 0);
                    }
                    piVar9 = *(int **)(iVar18 + 0x10);
                    if (piVar9 != (int *)0x0) {
                      iVar13 = 0;
                      do {
                        iVar18 = *piVar9;
                        puVar10 = (undefined2 *)(iStack_24 + iVar13);
                        iVar13 = iVar13 + 0x2c;
                        *puVar10 = *(undefined2 *)(iVar18 + 4);
                        puVar10[1] = *(undefined2 *)(iVar18 + 0x1c);
                        InitializeSharedStringRefFromEmpty();
                        iStack_4._0_1_ = 0x10;
                        StringShared__AssignFromPtr(&iStack_2c8,(int *)(iVar18 + 0x18));
                        iVar17 = 0;
                        do {
                          cVar5 = *(char *)(iVar17 + iStack_2c8);
                          *(char *)((int)puVar10 + iVar17 + 4) = cVar5;
                          if (cVar5 == '\0') break;
                          iVar17 = iVar17 + 1;
                        } while (iVar17 < 0x20);
                        sVar6 = *(short *)(iVar18 + 0x30);
                        *(undefined4 *)(puVar10 + 0x14) = 0x6e617679;
                        iStack_4._0_1_ = 5;
                        puVar10[0x12] =
                             (sVar6 / 100 + (sVar6 >> 0xf)) -
                             (short)((longlong)(int)sVar6 * 0x51eb851f >> 0x3f);
                        ReleaseSharedStringRefIfNotEmpty();
                        piVar9 = (int *)piVar9[1];
                      } while (piVar9 != (int *)0x0);
                    }
                    thunk_FUN_004a6e80(&uStack_274,0);
                    sVar6 = (short)iStack_2d0;
                    iVar13 = iStack_308;
                    if (bVar21) {
                      (**(code **)(*(int *)(&g_pTerrainTypeDescriptorTable)[sVar6] + 0x38))
                                (-((short)uStack_31c * iStack_2f4));
                      iVar13 = uStack_30c;
                      sVar15 = (short)uStack_30c;
                      (**(code **)(*(int *)(&g_pTerrainTypeDescriptorTable)[sVar15] + 0x38))
                                ((short)iStack_320 * iStack_2f8);
                      if (sVar15 < 7) {
                        *(int *)((&g_apNationStates)[sVar15] + 0x844) =
                             *(int *)((&g_apNationStates)[sVar15] + 0x844) -
                             (short)uStack_31c * iStack_2f4;
                      }
                      if (sVar6 < 7) {
                        *(int *)((&g_apNationStates)[sVar6] + 0x840) =
                             *(int *)((&g_apNationStates)[sVar6] + 0x840) -
                             (short)uStack_31c * iStack_2f4;
                      }
                    }
                    iVar18 = local_318;
                    if ((bVar2) && (sVar6 < 7)) {
                      thunk_FUN_004ddcf0(local_318,uStack_31c);
                    }
                    sVar16 = (short)iVar18;
                    sVar15 = (short)iVar13;
                    if (sVar6 < 7) {
                      if (bVar4) {
                        (**(code **)(*(int *)(&g_apNationStates)[sVar6] + 0x1c0))
                                  ((int)sVar16,(int)sVar15,0xfffe1dc0);
                      }
                      else if (bVar2) {
                        (**(code **)(*(int *)(&g_apNationStates)[sVar6] + 0x1c0))
                                  ((int)sVar16,(int)sVar15,0xfffe1dbf);
                      }
                    }
                    if (sVar15 < 7) {
                      if (bVar4) {
                        uVar7 = 0xfffe1dc0;
                        iVar13 = *(int *)(&g_apNationStates)[sVar15];
                      }
                      else {
                        if (!bVar2) goto LAB_0055961e;
                        uVar7 = 0xfffe1dbd;
                        iVar13 = *(int *)(&g_apNationStates)[sVar15];
                      }
                      (**(code **)(iVar13 + 0x1c0))((int)sVar16,(int)sVar6,uVar7);
                    }
LAB_0055961e:
                    iStack_4._0_1_ = 4;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4._0_1_ = 3;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4._0_1_ = 2;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4._0_1_ = 1;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4 = (uint)iStack_4._1_3_ << 8;
                    ReleaseSharedStringRefIfNotEmpty();
                    iStack_4 = 0xffffffff;
                    FreeHeapBufferIfNotNull(iStack_24);
                  }
                  FreeHeapBufferIfNotNull(puStack_20);
                  iVar13 = local_2d4;
                  iVar17 = local_318;
                }
              }
              iStack_2dc = iStack_2dc + 1;
              iVar18 = local_2ec;
            } while (iStack_2dc <= iStack_2a4);
          }
          local_318 = iVar17 + 1;
        } while ((short)local_318 < 0x11);
      }
    }
    local_2d4 = iVar13 + 1;
    if (6 < (short)local_2d4) {
      *unaff_FS_OFFSET = uStack_c;
      return;
    }
  } while( true );
}

