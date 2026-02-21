
undefined4 __thiscall Cluster_StateMachine18_4C_00545940(code *param_1,undefined4 *param_2)

{
  char cVar1;
  code cVar2;
  undefined2 uVar3;
  byte bVar4;
  bool bVar5;
  DiplomacyTurnStateManager *pDVar6;
  char cVar7;
  undefined1 uVar8;
  short sVar9;
  short sVar10;
  undefined4 uVar11;
  int *piVar12;
  undefined2 *puVar13;
  undefined4 *puVar14;
  HGLOBAL hMem;
  int *piVar15;
  undefined2 *puVar16;
  undefined2 *puVar17;
  uint uVar18;
  uint uVar19;
  code *pcVar20;
  undefined4 *puVar21;
  int iVar22;
  int iVar23;
  undefined4 unaff_EBX;
  char *pcVar24;
  uint uVar25;
  code *unaff_EBP;
  char *pcVar26;
  undefined4 *puVar27;
  undefined4 *puVar28;
  code *unaff_EDI;
  char *pcVar29;
  code *pcVar30;
  int iVar31;
  DiplomacyTurnStateManager *pDVar32;
  byte *pbVar33;
  undefined4 *unaff_FS_OFFSET;
  char *local_1d4;
  code *local_1d0;
  char local_1c9;
  char *local_1c8;
  code *local_1c4;
  char *local_1c0;
  char *local_1bc;
  undefined4 local_1b8 [5];
  undefined1 local_1a4;
  undefined4 local_1a0;
  int local_19c;
  char local_198 [33];
  char local_177 [3];
  char acStack_174 [32];
  int local_154 [2];
  int local_14c;
  int iStack_148;
  int local_144 [2];
  undefined1 uStack_13a;
  undefined1 uStack_139;
  undefined1 uStack_138;
  undefined1 uStack_137;
  undefined4 local_128;
  undefined4 local_124;
  undefined4 local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined1 local_114;
  undefined1 local_110 [256];
  char local_10;
  undefined1 local_f;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00634baf;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  local_1d0 = param_1;
  switch(*param_2) {
  case 1:
    uVar11 = 1;
    *(undefined4 *)(param_1 + 0xe8) = param_2[6];
    break;
  case 2:
    if (*(char *)(param_2 + 8) == '\0') {
      thunk_FUN_004f27f0();
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 3:
    *(undefined4 *)(param_1 + 0xd8) = 0x676f696e;
    *(undefined4 *)(param_1 + 0xec) = 0xffffffff;
    *(undefined4 *)(param_1 + 0xf0) = 0xffffffff;
    iVar23 = FUN_00405a3d();
    iVar31 = 0;
    piVar15 = (int *)(g_pGameFlowState + 0x48);
    do {
      if (*piVar15 == iVar23) goto LAB_00546c48;
      iVar31 = iVar31 + 1;
      piVar15 = piVar15 + 1;
    } while (iVar31 < 7);
    iVar31 = -1;
LAB_00546c48:
    if (iVar31 == -1) {
      puVar14 = (undefined4 *)AllocateWithFallbackHandler();
      local_4 = 0x12;
      local_1c4 = (code *)puVar14;
      if (puVar14 != (undefined4 *)0x0) {
        thunk_ConstructTurnEventPacketBase();
        *puVar14 = &PTR_LAB_0065bff0;
      }
      local_4 = 0xffffffff;
      thunk_FUN_004878a0();
      (**(code **)(*DAT_006a1344 + 0x38))();
      uVar11 = 1;
    }
    else {
      sVar10 = thunk_GetActiveNationId();
      iVar23 = (int)sVar10;
      if (iVar23 == -1) {
        iVar23 = (int)(char)param_1[0xdc];
      }
      *(undefined4 *)(param_1 + iVar23 * 4 + 0xbc) = 0x62757379;
      local_1b8[4] = 0x74696d65;
      local_1a4 = thunk_GetActiveNationId();
      local_1b8[1] = 0;
      local_1b8[0] = 0x25;
      local_1b8[3] = 0x34;
      puVar14 = &local_1a0;
      for (iVar31 = 7; iVar31 != 0; iVar31 = iVar31 + -1) {
        *puVar14 = 0x756e6b6e;
        puVar14 = puVar14 + 1;
      }
      local_1b8[2] = 0;
      (&local_1a0)[iVar23] = 0x62757379;
      thunk_FUN_005e3d40();
      (**(code **)(*g_pLocalizationTable + 0x44))();
      uVar11 = 1;
    }
    break;
  default:
    uVar11 = 0;
    break;
  case 8:
    cVar7 = *(char *)(param_2 + 6);
    iVar23 = (int)cVar7;
    if (iVar23 == -1) {
      thunk_FUN_005e42c0();
    }
    else if (*(int *)(param_1 + iVar23 * 4 + 0x48) != 0) {
      iVar31 = param_2[1];
      if (*(int *)(param_1 + iVar23 * 4 + 0x48) == iVar31) {
        thunk_FUN_005438e0();
        local_1b8[1] = 0;
        uVar25 = 0xffffffff;
        pcVar24 = (char *)((int)param_2 + 0x19);
        do {
          pcVar26 = pcVar24;
          if (uVar25 == 0) break;
          uVar25 = uVar25 - 1;
          pcVar26 = pcVar24 + 1;
          cVar1 = *pcVar24;
          pcVar24 = pcVar26;
        } while (cVar1 != '\0');
        uVar25 = ~uVar25;
        local_1b8[2] = 0;
        local_1b8[3] = 100;
        local_1b8[0] = 9;
        local_1a0 = CONCAT31(local_1a0._1_3_,cVar7);
        pcVar24 = pcVar26 + -uVar25;
        pcVar26 = local_198;
        for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
          *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
          pcVar24 = pcVar24 + 4;
          pcVar26 = pcVar26 + 4;
        }
        for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
          *pcVar26 = *pcVar24;
          pcVar24 = pcVar24 + 1;
          pcVar26 = pcVar26 + 1;
        }
        uVar25 = 0xffffffff;
        pcVar24 = (char *)((int)param_2 + 0x3a);
        do {
          pcVar26 = pcVar24;
          if (uVar25 == 0) break;
          uVar25 = uVar25 - 1;
          pcVar26 = pcVar24 + 1;
          cVar7 = *pcVar24;
          pcVar24 = pcVar26;
        } while (cVar7 != '\0');
        uVar25 = ~uVar25;
        pcVar24 = pcVar26 + -uVar25;
        pcVar26 = local_177;
        for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
          *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
          pcVar24 = pcVar24 + 4;
          pcVar26 = pcVar26 + 4;
        }
        for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
          *pcVar26 = *pcVar24;
          pcVar24 = pcVar24 + 1;
          pcVar26 = pcVar26 + 1;
        }
        local_19c = iVar31;
        thunk_FUN_005e3d40();
        uVar11 = 1;
      }
      else {
        local_118 = 0x74696d65;
        local_114 = thunk_GetActiveNationId();
        local_124 = 0;
        local_128 = 0xc;
        local_120 = 0;
        local_10 = 0xff;
        local_11c = 0x11c;
        thunk_GetActiveNationId();
        local_120 = param_2[1];
        local_f = 0xff;
        InitializeSharedStringRefFromEmpty();
        local_4 = 2;
        thunk_LoadUiStringResourceByGroupAndIndex();
        uVar25 = 0xffffffff;
        pcVar20 = local_1d0;
        do {
          pcVar30 = pcVar20;
          if (uVar25 == 0) break;
          uVar25 = uVar25 - 1;
          pcVar30 = pcVar20 + 1;
          cVar2 = *pcVar20;
          pcVar20 = pcVar30;
        } while (cVar2 != (code)0x0);
        uVar25 = ~uVar25;
        pcVar20 = pcVar30 + -uVar25;
        pcVar30 = (code *)local_110;
        for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
          *(undefined4 *)pcVar30 = *(undefined4 *)pcVar20;
          pcVar20 = pcVar20 + 4;
          pcVar30 = pcVar30 + 4;
        }
        for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
          *pcVar30 = *pcVar20;
          pcVar20 = pcVar20 + 1;
          pcVar30 = pcVar30 + 1;
        }
        thunk_FUN_005e3d40();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
      }
      break;
    }
    local_1c0 = (char *)0x0;
    pcVar20 = local_1d0 + 0x48;
    do {
      if (*(int *)pcVar20 == param_2[1]) {
        *(int *)pcVar20 = 0;
        *(int *)(pcVar20 + 0x74) = 0x756e6173;
        pcVar24 = PTR_DAT_0065bf18;
        local_1bc = PTR_DAT_0065bf18;
        thunk_FUN_005438e0();
        local_1b8[1] = 0;
        local_1a0 = CONCAT31(local_1a0._1_3_,local_1c0._0_1_);
        local_1b8[2] = 0;
        uVar25 = 0xffffffff;
        do {
          pcVar26 = pcVar24;
          if (uVar25 == 0) break;
          uVar25 = uVar25 - 1;
          pcVar26 = pcVar24 + 1;
          cVar1 = *pcVar24;
          pcVar24 = pcVar26;
        } while (cVar1 != '\0');
        uVar25 = ~uVar25;
        local_19c = 0;
        local_1b8[3] = 100;
        local_1b8[0] = 9;
        pcVar24 = pcVar26 + -uVar25;
        pcVar26 = local_198;
        for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
          *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
          pcVar24 = pcVar24 + 4;
          pcVar26 = pcVar26 + 4;
        }
        for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
          *pcVar26 = *pcVar24;
          pcVar24 = pcVar24 + 1;
          pcVar26 = pcVar26 + 1;
        }
        uVar25 = 0xffffffff;
        pcVar24 = local_1bc;
        do {
          pcVar26 = pcVar24;
          if (uVar25 == 0) break;
          uVar25 = uVar25 - 1;
          pcVar26 = pcVar24 + 1;
          cVar1 = *pcVar24;
          pcVar24 = pcVar26;
        } while (cVar1 != '\0');
        uVar25 = ~uVar25;
        pcVar24 = pcVar26 + -uVar25;
        pcVar26 = local_177;
        for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
          *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
          pcVar24 = pcVar24 + 4;
          pcVar26 = pcVar26 + 4;
        }
        for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
          *pcVar26 = *pcVar24;
          pcVar24 = pcVar24 + 1;
          pcVar26 = pcVar26 + 1;
        }
        thunk_FUN_005e3d40();
      }
      pcVar20 = pcVar20 + 4;
      local_1c0 = local_1c0 + 1;
    } while ((int)local_1c0 < 7);
    if (iVar23 != -1) {
      uVar11 = param_2[1];
      thunk_FUN_005438e0();
      uVar25 = 0xffffffff;
      pcVar24 = (char *)((int)param_2 + 0x19);
      do {
        pcVar26 = pcVar24;
        if (uVar25 == 0) break;
        uVar25 = uVar25 - 1;
        pcVar26 = pcVar24 + 1;
        cVar1 = *pcVar24;
        pcVar24 = pcVar26;
      } while (cVar1 != '\0');
      local_1b8[1] = 0;
      local_1b8[0] = 9;
      uVar25 = ~uVar25;
      local_1b8[2] = 0;
      local_1b8[3] = 100;
      local_1a0 = CONCAT31(local_1a0._1_3_,cVar7);
      pcVar24 = pcVar26 + -uVar25;
      pcVar26 = local_198;
      for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
        *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
        pcVar24 = pcVar24 + 4;
        pcVar26 = pcVar26 + 4;
      }
      for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
        *pcVar26 = *pcVar24;
        pcVar24 = pcVar24 + 1;
        pcVar26 = pcVar26 + 1;
      }
      uVar25 = 0xffffffff;
      pcVar24 = (char *)((int)param_2 + 0x3a);
      do {
        pcVar26 = pcVar24;
        if (uVar25 == 0) break;
        uVar25 = uVar25 - 1;
        pcVar26 = pcVar24 + 1;
        cVar7 = *pcVar24;
        pcVar24 = pcVar26;
      } while (cVar7 != '\0');
      uVar25 = ~uVar25;
      pcVar24 = pcVar26 + -uVar25;
      pcVar26 = local_177;
      for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
        *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
        pcVar24 = pcVar24 + 4;
        pcVar26 = pcVar26 + 4;
      }
      for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
        *pcVar26 = *pcVar24;
        pcVar24 = pcVar24 + 1;
        pcVar26 = pcVar26 + 1;
      }
      local_19c = uVar11;
      thunk_FUN_005e3d40();
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 9:
    cVar2 = *(code *)(param_2 + 6);
    if (cVar2 != (code)0xf3) {
      iVar23 = param_2[7];
      iVar22 = (int)(char)cVar2;
      ConstructSharedStringFromCStrOrResourceId();
      pcVar30 = local_1d0;
      local_4 = 3;
      StringShared__AssignFromPtr(local_1d0 + iVar22 * 4 + 0x78,local_154);
      local_4 = 0xffffffff;
      ReleaseSharedStringRefIfNotEmpty();
      ConstructSharedStringFromCStrOrResourceId();
      pcVar20 = pcVar30 + iVar22 * 4 + 0x94;
      local_4 = 4;
      StringShared__AssignFromPtr(pcVar20,&local_14c);
      local_4 = 0xffffffff;
      ReleaseSharedStringRefIfNotEmpty();
      local_1bc = *(char **)(pcVar30 + iVar22 * 4 + 0x48);
      *(int *)(pcVar30 + iVar22 * 4 + 0x48) = iVar23;
      iVar31 = FUN_00405a3d();
      if ((iVar23 == iVar31) && (iVar23 != 0)) {
        local_1c9 = 1;
        pcVar30[0xdc] = cVar2;
      }
      else {
        local_1c9 = 0;
      }
      InitializeSharedStringRefFromEmpty();
      local_4 = 5;
      if (iVar23 == 0) {
        thunk_LoadUiStringResourceByGroupAndIndex();
        *(undefined4 *)(pcVar30 + iVar22 * 4 + 0xbc) = 0x756e6173;
      }
      else {
        StringShared__AssignFromPtr(&local_1c0,(int *)pcVar20);
        if ((*(int *)(pcVar30 + 0xd8) == 0x676f696e) &&
           (sVar10 = thunk_GetActiveNationId(), sVar10 != -1)) {
          bVar4 = 1;
        }
        else {
          bVar4 = 0;
        }
        *(uint *)(pcVar30 + iVar22 * 4 + 0xbc) = (-(uint)bVar4 & 0xf0100f00) + 0x72656479;
      }
      StringShared__AssignFromPtr(pcVar20,(int *)&local_1c0);
      StringShared__AssignFromPtr(pcVar30 + iVar22 * 4 + 0x78,(int *)pcVar20);
      piVar15 = *(int **)(pcVar30 + 0x40);
      if ((piVar15 == (int *)0x0) ||
         (iVar31 = IsNodePresentInLinkedListByNextPointer(), iVar31 == 0)) {
        iVar31 = 0;
      }
      else {
        iVar31 = *(int *)(pcVar30 + 0x40);
      }
      if (iVar31 != 0) {
        local_1d0 = *(code **)(*piVar15 + 0x94);
        piVar12 = (int *)(*local_1d0)();
        iVar31 = *piVar12;
        (**(code **)(iVar31 + 0xc))();
        thunk_FUN_00508c50();
        puStack_8 = (undefined1 *)CONCAT31(puStack_8._1_3_,6);
        (**(code **)(iVar31 + 0x1c8))();
        if ((char)((uint)unaff_EBX >> 0x18) == '\0') {
          iVar22 = 0x2b6c;
          iVar31 = 0x2b6b;
        }
        else {
          iVar22 = 0x2b6b;
          iVar31 = 0x2b6c;
        }
        thunk_ApplyUiTextStyleAndThemeFlags(piVar12,0,0xe,iVar31,iVar22);
        iVar31 = FUN_00405a3d();
        if ((local_1bc == (char *)iVar31) || (iVar31 = FUN_00405a3d(), iVar23 == iVar31)) {
          iVar23 = 6;
          pcVar20 = pcVar30 + 0x60;
          do {
            iVar31 = FUN_00405a3d();
            if (*(int *)pcVar20 == iVar31) break;
            iVar23 = iVar23 + -1;
            pcVar20 = pcVar20 + -4;
          } while (-1 < iVar23);
          piVar12 = (int *)(*local_1d0)();
          iVar31 = *piVar12;
          (**(code **)(iVar31 + 0xc))();
          piVar12[0x1a] = iVar23;
          thunk_FUN_00579270();
          (**(code **)(iVar31 + 0x128))();
          thunk_ConstructScopedMapQuickDrawContext();
          local_c = CONCAT31(local_c._1_3_,7);
          (**(code **)(unaff_EBP + 0x110))();
          piVar12 = (int *)(*unaff_EBP)();
          unaff_EDI = (code *)*piVar12;
          (**(code **)(unaff_EDI + 0xc))();
          if (-1 < iVar23) {
            (**(code **)(unaff_EDI + 0x1c8))();
          }
          (**(code **)(unaff_EDI + 0xa4))();
          local_4 = CONCAT31(local_4._1_3_,6);
          thunk_DestroyScopedMapQuickDrawContext();
        }
        if (g_pLocalizationTable[0x11] == 1) {
          bVar5 = false;
          local_1c8 = (char *)0x0;
          pcVar30 = pcVar30 + 0x48;
          iVar23 = 7;
          do {
            if (*(int *)pcVar30 != 0) {
              local_1c8 = local_1c8 + 1;
              iVar31 = FUN_00405a3d();
              if (*(int *)pcVar30 == iVar31) {
                bVar5 = true;
              }
            }
            pcVar30 = pcVar30 + 4;
            iVar23 = iVar23 + -1;
          } while (iVar23 != 0);
          if (((int)local_1c8 < 2) || (!bVar5)) {
            bVar5 = false;
          }
          else {
            bVar5 = true;
          }
          piVar12 = (int *)(*local_1d0)();
          iVar23 = *piVar12;
          (**(code **)(iVar23 + 0xc))();
          InitializeSharedStringRefFromEmpty();
          puStack_8 = (undefined1 *)CONCAT31(puStack_8._1_3_,8);
          thunk_LoadUiStringResourceByGroupAndIndex();
          if (bVar5) {
            StringShared__AssignFromPtr(piVar12 + 0x25,(int *)&stack0xfffffe28);
            (**(code **)(iVar23 + 0xe4))();
          }
          (**(code **)(iVar23 + 0xa8))();
          (**(code **)(iVar23 + 0xa4))();
          *(undefined2 *)((int)piVar12 + 0x9a) = 0x2b6c;
          *(undefined2 *)(piVar12 + 0x27) = 0x2b6b;
          *(undefined2 *)(piVar12 + 0x26) = 0xc;
          piVar12 = (int *)(*unaff_EDI)();
          iVar23 = *piVar12;
          (**(code **)(iVar23 + 0xc))();
          (**(code **)(iVar23 + 0xa4))();
          thunk_FUN_005c4910();
          iVar23 = *piVar15;
          (**(code **)(iVar23 + 0xc))();
          (**(code **)(iVar23 + 0x1c8))();
          local_4 = CONCAT31(local_4._1_3_,6);
          ReleaseSharedStringRefIfNotEmpty();
        }
        local_4 = CONCAT31(local_4._1_3_,5);
        ReleaseSharedStringRefIfNotEmpty();
      }
      local_4 = 0xffffffff;
      ReleaseSharedStringRefIfNotEmpty();
      uVar11 = 1;
      break;
    }
    if (g_pLocalizationTable[0x11] == 1) {
      pcVar24 = *(char **)(param_1 + 0xb4);
      pcVar26 = *(char **)(param_1 + 0xb0);
      uVar11 = FUN_00405a3d();
      local_1bc = (char *)CONCAT22(local_1bc._2_2_,(short)(char)param_1[0xdc]);
      thunk_FUN_005438e0();
      uVar25 = 0xffffffff;
      local_1a0 = CONCAT31(local_1a0._1_3_,local_1bc._0_1_);
      do {
        pcVar29 = pcVar26;
        if (uVar25 == 0) break;
        uVar25 = uVar25 - 1;
        pcVar29 = pcVar26 + 1;
        cVar7 = *pcVar26;
        pcVar26 = pcVar29;
      } while (cVar7 != '\0');
      local_1b8[0] = 9;
      local_1b8[1] = 0;
      uVar25 = ~uVar25;
      local_1b8[2] = 0;
      local_1b8[3] = 100;
      pcVar26 = pcVar29 + -uVar25;
      pcVar29 = local_198;
      for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
        *(undefined4 *)pcVar29 = *(undefined4 *)pcVar26;
        pcVar26 = pcVar26 + 4;
        pcVar29 = pcVar29 + 4;
      }
      for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
        *pcVar29 = *pcVar26;
        pcVar26 = pcVar26 + 1;
        pcVar29 = pcVar29 + 1;
      }
      uVar25 = 0xffffffff;
      do {
        pcVar26 = pcVar24;
        if (uVar25 == 0) break;
        uVar25 = uVar25 - 1;
        pcVar26 = pcVar24 + 1;
        cVar7 = *pcVar24;
        pcVar24 = pcVar26;
      } while (cVar7 != '\0');
      uVar25 = ~uVar25;
      pcVar24 = pcVar26 + -uVar25;
      pcVar26 = local_177;
      for (uVar18 = uVar25 >> 2; uVar18 != 0; uVar18 = uVar18 - 1) {
        *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
        pcVar24 = pcVar24 + 4;
        pcVar26 = pcVar26 + 4;
      }
      for (uVar25 = uVar25 & 3; uVar25 != 0; uVar25 = uVar25 - 1) {
        *pcVar26 = *pcVar24;
        pcVar24 = pcVar24 + 1;
        pcVar26 = pcVar26 + 1;
      }
      local_19c = uVar11;
      thunk_FUN_005e3d40();
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 10:
    if ((short)g_pLocalizationTable[0x45] == 0) {
      (**(code **)(*g_pGlobalMapState + 0x134))();
      thunk_RefreshNationCivilianWorkOrdersForTurn();
    }
    *(uint *)(param_1 + 0xe8) = *(uint *)(param_1 + 0xe8) & ~(1 << (*(byte *)(param_2 + 7) & 0x1f));
    if (g_pLocalizationTable[0x11] == 1) {
      thunk_FUN_005438e0();
      local_1a0 = *(uint *)(param_1 + 0xe8);
LAB_00545aa0:
      local_1b8[3] = 0x1c;
      local_1b8[2] = 0;
      local_1b8[1] = 0;
      local_1b8[0] = 1;
      thunk_FUN_005e3d40();
      if ((*(int *)(param_1 + 0xe8) == 0) && (*(int *)(param_1 + 0xf0) != -1)) {
        thunk_FUN_00543910();
        uVar11 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0xb:
    iVar23 = 0;
    param_2 = param_2 + 7;
    piVar15 = &g_pTerrainTypeDescriptorTable;
    do {
      sVar10 = thunk_GetActiveNationId();
      if ((iVar23 != sVar10) && (cVar7 = (**(code **)(*(int *)*piVar15 + 0xa0))(), cVar7 != '\0')) {
        (**(code **)(*(int *)*piVar15 + 0xa4))();
        ConstructSharedStringFromCStrOrResourceId();
        local_4 = 0;
        thunk_FUN_004d7a00();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        ConstructSharedStringFromCStrOrResourceId();
        local_4 = 1;
        StringShared__AssignFromPtr((void *)(*piVar15 + 8),&iStack_148);
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        if ((short)g_pLocalizationTable[0x45] == 0) {
          (**(code **)(*g_pGlobalMapState + 0x134))();
        }
      }
      iVar31 = FindFirstPortZoneContextByNation();
      puVar14 = param_2 + 0x187;
      piVar15 = piVar15 + 1;
      iVar23 = iVar23 + 1;
      param_2 = (undefined4 *)((int)param_2 + 2);
      *(undefined2 *)(iVar31 + 0x14) = *(undefined2 *)puVar14;
    } while ((int)piVar15 < 0x6a436c);
    thunk_FUN_0054cc00();
    uVar11 = 1;
    break;
  case 0xc:
    sVar10 = thunk_GetActiveNationId();
    local_1d4 = (char *)(int)sVar10;
    if (local_1d4 == (char *)0xffffffff) {
      iVar23 = FUN_00405a3d();
      local_1d4 = (char *)0x0;
      piVar15 = (int *)(g_pGameFlowState + 0x48);
      do {
        if (*piVar15 == iVar23) goto LAB_005464f4;
        local_1d4 = local_1d4 + 1;
        piVar15 = piVar15 + 1;
      } while ((int)local_1d4 < 7);
      local_1d4 = (char *)0xffffffff;
LAB_005464f4:
      if (local_1d4 != (char *)0xffffffff) goto LAB_005464fd;
    }
    else {
LAB_005464fd:
      if ((*(byte *)(param_2 + 0x46) & (byte)(1 << ((byte)local_1d4 & 0x1f))) == 0)
      goto LAB_005485d8;
    }
    pcVar24 = (char *)(int)*(char *)((int)param_2 + 0x119);
    local_1c8 = pcVar24;
    ConstructSharedStringFromCStrOrResourceId();
    local_4 = 9;
    InitializeSharedStringRefFromEmpty();
    local_4._0_1_ = 10;
    InitializeSharedStringRefFromEmpty();
    local_4 = CONCAT31(local_4._1_3_,0xb);
    if ((pcVar24 == (char *)0xffffffff) || (pcVar24 == local_1d4)) {
      thunk_BuildUiMessageTextFromBracketTemplate();
    }
    else {
      (**(code **)(*g_pLocalizationTable + 0x84))();
      scanBracketExpressions(g_pLocalizationTable,&local_1d0,local_1c0);
    }
    uStack_13a = 0;
    uStack_139 = 0;
    uStack_138 = 0;
    uStack_137 = 0;
    BuildUiTextStyleDescriptor();
    piVar15 = (int *)(**(code **)(*g_pUiViewManager + 0x28))();
    if (piVar15 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    iVar23 = *piVar15;
    (**(code **)(iVar23 + 0x1a0))();
    iVar31 = (**(code **)(iVar23 + 0x1b8))();
    if (iVar31 != 0) {
      *(undefined4 *)(iVar31 + 0x14) = 0x6f6b6179;
    }
    (**(code **)(*g_pUiRuntimeContext + 0x44))();
    (**(code **)(iVar23 + 0xf0))();
    pcVar20 = *(code **)(iVar23 + 0x94);
    piVar12 = (int *)(*pcVar20)();
    iVar23 = *piVar12;
    (**(code **)(iVar23 + 0xc))();
    if (piVar12 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    (**(code **)(iVar23 + 0x1c8))();
    iVar31 = 0x636f6174;
    piVar12 = (int *)(*pcVar20)();
    iVar23 = *piVar12;
    (**(code **)(iVar23 + 0xc))();
    if (piVar12 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    (**(code **)(iVar23 + 0x1c8))();
    piVar12 = (int *)(*pcVar20)(0x7469746c);
    iVar23 = *piVar12;
    (**(code **)(iVar23 + 0xc))();
    if (piVar12 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    (**(code **)(iVar23 + 0x1b4))(local_177 + 3,0);
    (**(code **)(iVar23 + 0x1c4))(1,0);
    (**(code **)(iVar23 + 0x1c8))(&stack0xfffffdec,0);
    piVar12 = (int *)(*pcVar20)();
    iVar23 = *piVar12;
    (**(code **)(iVar23 + 0xc))();
    (**(code **)(iVar23 + 500))(iVar31,*(undefined4 *)(iVar31 + -8));
    (**(code **)(iVar23 + 0x1e4))(local_198,0);
    *(undefined1 *)(g_pGameFlowState + 0x68) = 0;
    piVar12 = (int *)(*pcVar20)(0x636e636c);
    iVar23 = *piVar12;
    (**(code **)(iVar23 + 0xc))();
    piVar12[7] = 0x72737670;
    (**(code **)(iVar23 + 0xa4))(1,0);
    (**(code **)(iVar23 + 0xa8))(1,0);
    (**(code **)(iVar23 + 0x1c8))(0x53a,0);
    iVar23 = *piVar15;
    iVar31 = (**(code **)(iVar23 + 0x1ac))();
    (**(code **)(iVar23 + 0xa0))();
    (**(code **)(iVar23 + 0x1c))();
    if (iVar31 == 0x72737670) {
      puVar14 = (undefined4 *)AllocateWithFallbackHandler();
      local_4._0_1_ = 0xc;
      local_1c4 = (code *)puVar14;
      if (puVar14 == (undefined4 *)0x0) {
        puVar14 = (undefined4 *)0x0;
      }
      else {
        thunk_ConstructTurnEventPacketBase();
        *puVar14 = &PTR_LAB_0065c0e8;
      }
      puVar14[6] = local_1c8;
      local_4 = CONCAT31(local_4._1_3_,0xb);
      thunk_FUN_004878a0();
      (**(code **)(*DAT_006a1344 + 0x38))();
    }
    local_4._0_1_ = 10;
    *(char *)(g_pGameFlowState + 0x68) = local_1c9;
    ReleaseSharedStringRefIfNotEmpty();
    local_4 = CONCAT31(local_4._1_3_,9);
    ReleaseSharedStringRefIfNotEmpty();
    local_4 = 0xffffffff;
    ReleaseSharedStringRefIfNotEmpty();
    uVar11 = 1;
    break;
  case 0xd:
    thunk_FUN_0054c8e0();
    uVar11 = 1;
    break;
  case 0xe:
    thunk_FUN_0057d870();
    *(undefined1 *)(g_pLocalizationTable + 0x1a) = *(undefined1 *)((int)param_2 + 0x65);
    ConstructSharedStringFromCStrOrResourceId();
    local_4 = 0xd;
    StringShared__AssignFromPtr(param_1 + 0x74,local_144);
    local_4 = 0xffffffff;
    ReleaseSharedStringRefIfNotEmpty();
    uVar25 = param_2[0x18];
    *(uint *)(param_1 + 0xe0) = uVar25;
    *(undefined4 *)(param_1 + 100) = param_2[0x17];
    *(undefined4 *)(param_1 + 0xd8) = 0x696e6974;
    if (uVar25 == 0x6c6f6164) {
      cVar7 = thunk_FUN_0056df40();
      if (cVar7 == '\0') {
        InitializeSharedStringRefFromEmpty();
        local_4 = 0xe;
        thunk_LoadUiStringResourceByGroupAndIndex();
        local_1c4 = (code *)&stack0xfffffe0c;
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
        puVar14 = (undefined4 *)AllocateWithFallbackHandler();
        local_4._0_1_ = 0xf;
        local_1c4 = (code *)puVar14;
        if (puVar14 != (undefined4 *)0x0) {
          thunk_ConstructTurnEventPacketBase();
          *puVar14 = &PTR_LAB_0065bff0;
        }
        local_4 = CONCAT31(local_4._1_3_,0xe);
        thunk_FUN_004878a0();
        (**(code **)(*DAT_006a1344 + 0x38))();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
      }
      else {
        *(undefined4 *)(g_pGameFlowState + 0x40) = 0;
        *(undefined4 *)(g_pGameFlowState + 0xd8) = 0x676f696e;
        thunk_FUN_0054cc00();
        uVar11 = 1;
      }
      break;
    }
    if (uVar25 == 0x72616e64) {
      RebuildGlobalOrderManagersAndCapabilityState();
      thunk_RebuildMapContextAndGlobalMapState();
    }
    else {
      if ((uVar25 < 0x73636e30) || (0x73637a39 < uVar25)) goto LAB_005485d8;
      RebuildGlobalOrderManagersAndCapabilityState();
      cVar7 = thunk_FUN_0057c9a0();
      if (cVar7 == '\0') {
        InitializeSharedStringRefFromEmpty();
        local_4 = 0x10;
        thunk_LoadUiStringResourceByGroupAndIndex();
        local_1c4 = (code *)&stack0xfffffe0c;
        thunk_AssignStringSharedRefAndReturnThis();
        thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
        puVar14 = (undefined4 *)AllocateWithFallbackHandler();
        local_4._0_1_ = 0x11;
        local_1c4 = (code *)puVar14;
        if (puVar14 != (undefined4 *)0x0) {
          thunk_ConstructTurnEventPacketBase();
          *puVar14 = &PTR_LAB_0065bff0;
        }
        local_4 = CONCAT31(local_4._1_3_,0x10);
        thunk_FUN_004878a0();
        (**(code **)(*DAT_006a1344 + 0x38))();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
        break;
      }
    }
    if ((*(int *)(param_1 + 0x40) == 0) ||
       (iVar23 = IsNodePresentInLinkedListByNextPointer(), iVar23 == 0)) {
      thunk_FUN_0054e4c0();
      uVar11 = 1;
    }
    else {
      thunk_FUN_0054e4c0();
      uVar11 = 1;
    }
    break;
  case 0xf:
    *(uint *)(param_1 + 0xe8) = *(uint *)(param_1 + 0xe8) & ~(1 << (*(byte *)(param_2 + 7) & 0x1f));
    if (g_pLocalizationTable[0x11] == 1) {
      thunk_FUN_005438e0();
      local_1a0 = *(uint *)(param_1 + 0xe8);
      goto LAB_00545aa0;
    }
    goto LAB_005485d8;
  case 0x10:
    (**(code **)(*g_pLocalizationTable + 0x44))();
    uVar11 = 1;
    break;
  case 0x11:
    cVar7 = *(char *)(param_2 + 6);
    if (cVar7 == '\x01') {
      iVar23 = 0;
      if (param_2[7] == 0) {
        iVar23 = g_pGlobalMapState[3];
      }
      else if (param_2[7] == 1) {
        iVar23 = g_pGlobalMapState[4];
      }
      *(byte *)(param_2[8] + iVar23) =
           *(byte *)(param_2[8] + iVar23) & ~*(byte *)((int)param_2 + 0x26) |
           *(byte *)(param_2 + 9) & *(byte *)((int)param_2 + 0x26);
    }
    else if (cVar7 == '\x02') {
      iVar23 = 0;
      if (param_2[7] == 0) {
        iVar23 = g_pGlobalMapState[3];
      }
      else if (param_2[7] == 1) {
        iVar23 = g_pGlobalMapState[4];
      }
      *(ushort *)(param_2[8] + iVar23) =
           *(ushort *)(param_2[8] + iVar23) & ~*(ushort *)((int)param_2 + 0x26) |
           *(ushort *)(param_2 + 9) & *(ushort *)((int)param_2 + 0x26);
    }
    else if (cVar7 == '\x04') {
      iVar23 = 0;
      if (param_2[7] == 0) {
        iVar23 = g_pGlobalMapState[3];
      }
      else if (param_2[7] == 1) {
        iVar23 = g_pGlobalMapState[4];
      }
      *(uint *)(param_2[8] + iVar23) =
           (int)(short)(*(ushort *)(param_2 + 9) & *(ushort *)((int)param_2 + 0x26)) |
           *(uint *)(param_2[8] + iVar23) & ~(int)(short)*(ushort *)((int)param_2 + 0x26);
    }
    if (g_pLocalizationTable[0x11] == 1) {
      puVar14 = local_1b8;
      for (iVar23 = 10; iVar23 != 0; iVar23 = iVar23 + -1) {
        *puVar14 = *param_2;
        param_2 = param_2 + 1;
        puVar14 = puVar14 + 1;
      }
      local_1b8[1] = 0;
      local_1b8[0] = 0x11;
      local_1b8[3] = 0x28;
      local_1b8[2] = 0;
      thunk_FUN_005e3d40();
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x12:
    (**(code **)(*g_pGlobalMapState + 0xb8))();
    uVar11 = 1;
    break;
  case 0x13:
    thunk_QueueInterNationEventIntoNationBucket
              (g_pInterNationEventQueueManager,(int)*(short *)(param_2 + 6),(sdword)(param_2 + 7),
               '\x01');
    uVar11 = 1;
    break;
  case 0x14:
    (**(code **)(*(int *)(&g_pTerrainTypeDescriptorTable)[*(short *)(param_2 + 6)] + 0x38))();
    uVar11 = 1;
    break;
  case 0x15:
    local_1c8 = (char *)0x17;
    iVar23 = (&g_apNationStates)[*(short *)(param_2 + 6)];
    *(undefined4 *)(iVar23 + 0x10) = param_2[7];
    puVar14 = param_2 + 0x43;
    puVar27 = (undefined4 *)(iVar23 + 0x280);
    *(undefined4 *)(iVar23 + 0xac) = param_2[8];
    puVar16 = (undefined2 *)(iVar23 + 0x13c);
    puVar13 = (undefined2 *)((int)param_2 + 0x52);
    do {
      puVar16[-0x17] = puVar13[-0x17];
      *puVar16 = *puVar13;
      puVar16[0x17] = puVar13[0x17];
      puVar16[0x2e] = puVar13[0x2e];
      puVar16[0x45] = puVar13[0x45];
      iVar31 = 0x10;
      puVar21 = puVar14;
      puVar28 = puVar27;
      do {
        uVar11 = *puVar21;
        puVar21 = puVar21 + 0x17;
        *puVar28 = uVar11;
        puVar28 = puVar28 + 0x17;
        iVar31 = iVar31 + -1;
      } while (iVar31 != 0);
      puVar13 = puVar13 + 1;
      puVar16 = puVar16 + 1;
      puVar27 = puVar27 + 1;
      puVar14 = puVar14 + 1;
      local_1c8 = local_1c8 + -1;
    } while (local_1c8 != (char *)0x0);
    *(undefined4 *)(iVar23 + 0x840) = param_2[0x1b3];
    *(undefined4 *)(iVar23 + 0x844) = param_2[0x1b4];
    *(undefined4 *)(iVar23 + 0x8f0) = param_2[0x1b5];
    *(undefined1 *)(iVar23 + 0x8f4) = *(undefined1 *)(param_2 + 0x1b6);
    *(undefined4 *)(iVar23 + 0x8f8) = param_2[0x1b7];
    *(undefined1 *)(iVar23 + 0x8fc) = *(undefined1 *)(param_2 + 0x1b8);
    uVar11 = 1;
    break;
  case 0x16:
    (**(code **)(*(int *)(&g_apNationStates)[*(short *)(param_2 + 6)] + 0x8c))();
    uVar11 = 1;
    break;
  case 0x17:
    if (*(char *)((int)param_2 + 0x1a) == '\0') {
      (**(code **)(*(int *)(&g_apNationStates)[*(short *)(param_2 + 6)] + 0x1f0))();
      uVar11 = 1;
    }
    else {
      (**(code **)(*(int *)(&g_apNationStates)[*(short *)(param_2 + 6)] + 0x1ec))();
      uVar11 = 1;
    }
    break;
  case 0x18:
    piVar15 = &g_apNationStates;
    puVar13 = (undefined2 *)((int)param_2 + 0x15e);
    do {
      if (*piVar15 != 0) {
        puVar17 = (undefined2 *)(*piVar15 + 0xe0);
        iVar23 = 0x17;
        puVar16 = puVar13;
        do {
          puVar17[-0x17] = puVar16[-0xa1];
          *puVar17 = *puVar16;
          puVar17[-0x66] = puVar16[0xa1];
          puVar17 = puVar17 + 1;
          iVar23 = iVar23 + -1;
          puVar16 = puVar16 + 1;
        } while (iVar23 != 0);
      }
      piVar15 = piVar15 + 1;
      puVar13 = puVar13 + 0x17;
    } while ((int)piVar15 < 0x6a438c);
    uVar11 = 1;
    break;
  case 0x19:
    sVar10 = *(short *)(param_2 + 7);
    sVar9 = thunk_GetActiveNationId();
    if (sVar10 != sVar9) {
      piVar15 = (int *)(&g_apNationStates)[sVar10];
      iVar23 = 0x5c;
      *(undefined2 *)((int)piVar15 + 0xa6) = *(undefined2 *)((int)param_2 + 0x1e);
      do {
        *(undefined2 *)(iVar23 + piVar15[0x225]) = *(undefined2 *)((int)param_2 + iVar23 + -0x3c);
        iVar23 = iVar23 + 2;
      } while (iVar23 < 0x78);
      iVar23 = *piVar15;
      (**(code **)(iVar23 + 0x164))();
      local_1c4 = *(code **)(iVar23 + 0x18c);
      iVar23 = 0;
      do {
        (*local_1c4)();
        iVar23 = iVar23 + 1;
      } while (iVar23 < 0x17);
      iVar23 = *piVar15;
      (**(code **)(iVar23 + 0x168))();
      local_1c4 = *(code **)(iVar23 + 0x1a4);
      iVar23 = 0;
      do {
        (*local_1c4)();
        iVar23 = iVar23 + 1;
      } while (iVar23 < 0x11);
      (**(code **)(*piVar15 + 0x1a8))();
      piVar15 = piVar15 + 0x38;
      iVar23 = 0x17;
      puVar13 = (undefined2 *)((int)param_2 + 0xba);
      do {
        *(undefined2 *)((int)piVar15 + -0x2e) = puVar13[-0x17];
        *(undefined2 *)piVar15 = *puVar13;
        *(undefined2 *)(piVar15 + -0x33) = puVar13[0x17];
        piVar15 = (int *)((int)piVar15 + 2);
        iVar23 = iVar23 + -1;
        puVar13 = puVar13 + 1;
      } while (iVar23 != 0);
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x1a:
    if (g_pLocalizationTable[0x11] == 2) {
      piVar15 = &g_apNationStates;
      puVar13 = (undefined2 *)((int)param_2 + 0x26);
      do {
        if (*piVar15 != 0) {
          *(undefined2 *)(*piVar15 + 0xa2) = *puVar13;
        }
        piVar15 = piVar15 + 1;
        puVar13 = puVar13 + 1;
      } while ((int)piVar15 < 0x6a438c);
    }
    sVar10 = *(short *)(param_2 + 7);
    sVar9 = thunk_GetActiveNationId();
    if (sVar10 != sVar9) {
      (**(code **)(*g_pUiRuntimeContext + 0x98))();
      uVar11 = 1;
      break;
    }
    if (g_pLocalizationTable[0x11] == 2) {
      (**(code **)(*g_pUiRuntimeContext + 0x98))();
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x1b:
    (**(code **)(*(int *)(&g_apNationStates)[*(short *)(param_2 + 7)] + 0x1b0))();
    uVar11 = 1;
    break;
  case 0x1c:
    (**(code **)(g_pNationInteractionStateManager->vftable + 0x60))();
    if (g_pLocalizationTable[0x11] == 1) {
      local_1c4 = (code *)AllocateWithFallbackHandler();
      local_4 = 0x14;
      if (local_1c4 != (code *)0x0) {
        thunk_FUN_005ba400();
      }
      local_4 = 0xffffffff;
      thunk_FUN_005ba480();
      (**(code **)(*DAT_006a1344 + 0x38))();
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x1d:
    sVar10 = thunk_GetActiveNationId();
    if (*(char *)(param_2 + 7) == 'i') {
      (**(code **)(*(int *)(&g_apNationStates)[sVar10] + 0x27c))();
      uVar11 = 1;
    }
    else {
      (**(code **)(*(int *)(&g_apNationStates)[sVar10] + 0x280))();
      uVar11 = 1;
    }
    break;
  case 0x1e:
    if (*(char *)((int)param_2 + 0x1f) == 'a') {
      if (*(char *)((int)param_2 + 0x21) == '\0') {
        (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x7c))();
      }
      else if (*(char *)(param_2 + 8) == '\0') {
        (**(code **)(*(int *)(&g_apNationStates)[*(char *)(param_2 + 7)] + 0x284))();
      }
      else {
        (**(code **)(*(int *)(&g_apNationStates)[*(char *)(param_2 + 7)] + 0x284))();
      }
    }
    else if ((*(char *)((int)param_2 + 0x1f) == 'i') && (*(char *)((int)param_2 + 0x21) != '\0')) {
      cVar7 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))();
      if (cVar7 == '\0') {
        (**(code **)(*(int *)(&g_apNationStates)[*(char *)(param_2 + 7)] + 0x284))();
      }
      else {
        piVar15 = (int *)(&DAT_006a4280)[*(char *)((int)param_2 + 0x1d)];
        sVar10 = *(short *)((int)piVar15 + 0xe);
        if (sVar10 < 200) {
          if (sVar10 < 100) {
            sVar10 = (short)piVar15[3];
          }
          else {
            sVar10 = sVar10 + -100;
          }
        }
        else {
          sVar10 = sVar10 + -200;
        }
        if (sVar10 != *(char *)(param_2 + 7)) {
          (**(code **)(*piVar15 + 0x4c))();
        }
      }
    }
    puVar14 = (undefined4 *)AllocateWithFallbackHandler();
    local_4 = 0x13;
    local_1c4 = (code *)puVar14;
    if (puVar14 != (undefined4 *)0x0) {
      thunk_ConstructTurnEventPacketBase();
      *puVar14 = &PTR_LAB_00654e50;
    }
    local_4 = 0xffffffff;
    thunk_DispatchUiPacketWithTagNEXT();
    uVar11 = 1;
    break;
  case 0x1f:
    uVar25 = param_2[6];
    if (uVar25 < 0x61636565) {
      if (uVar25 == 0x61636564) {
        sVar10 = thunk_GetActiveNationId();
        iVar23 = param_2[7];
        InitializeSharedStringRefFromEmpty();
        local_4 = 0x1f;
        InitializeSharedStringRefFromEmpty();
        local_4._0_1_ = 0x20;
        InitializeSharedStringRefFromEmpty();
        local_4 = CONCAT31(local_4._1_3_,0x21);
        thunk_LoadUiStringResourceByGroupAndIndex();
        FormatOverlayTerrainLabelText();
        scanBracketExpressions(g_pLocalizationTable,&local_1c8,(char *)local_1d0);
        thunk_FUN_005dea60();
        if (sVar10 == iVar23) {
          thunk_FUN_0049e500();
        }
        local_4._0_1_ = 0x20;
        ReleaseSharedStringRefIfNotEmpty();
        local_4 = CONCAT31(local_4._1_3_,0x1f);
        ReleaseSharedStringRefIfNotEmpty();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x61626469) {
        InitializeSharedStringRefFromEmpty();
        local_4 = 0x1c;
        InitializeSharedStringRefFromEmpty();
        local_4._0_1_ = 0x1d;
        InitializeSharedStringRefFromEmpty();
        local_4 = CONCAT31(local_4._1_3_,0x1e);
        thunk_LoadUiStringResourceByGroupAndIndex();
        FormatOverlayTerrainLabelText();
        scanBracketExpressions(g_pLocalizationTable,&local_1c8,(char *)local_1d0);
        thunk_FUN_005dea60();
        if (g_pLocalizationTable[0x11] == 1) {
          thunk_FUN_0054bd20();
        }
        local_4._0_1_ = 0x1d;
        ReleaseSharedStringRefIfNotEmpty();
        local_4 = CONCAT31(local_4._1_3_,0x1c);
        ReleaseSharedStringRefIfNotEmpty();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
        break;
      }
    }
    else if (uVar25 < 0x64656876) {
      if (uVar25 == 0x64656875) {
        thunk_FUN_0054bd20();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x6367616d) {
        puVar14 = (undefined4 *)AllocateWithFallbackHandler();
        local_4 = 0x25;
        local_1c4 = (code *)puVar14;
        if (puVar14 != (undefined4 *)0x0) {
          thunk_ConstructTurnEventPacketBase();
          *puVar14 = &PTR_LAB_0065bff0;
        }
        local_4 = 0xffffffff;
        thunk_FUN_004878a0();
        (**(code **)(*DAT_006a1344 + 0x38))();
        InitializeSharedStringRefFromEmpty();
        local_4 = 0x26;
        thunk_LoadUiStringResourceByGroupAndIndex();
        thunk_FUN_005dea60();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
        break;
      }
    }
    else if (uVar25 < 0x6c6f7366) {
      if (uVar25 == 0x6c6f7365) {
        (**(code **)(*(int *)(&g_apNationStates)[param_2[7]] + 0x2ac))();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x666f6666) {
        InitializeSharedStringRefFromEmpty();
        local_4 = 0x1a;
        thunk_LoadUiStringResourceByGroupAndIndex();
        thunk_FUN_005dea60();
        puVar14 = (undefined4 *)AllocateWithFallbackHandler();
        local_4._0_1_ = 0x1b;
        local_1c4 = (code *)puVar14;
        if (puVar14 != (undefined4 *)0x0) {
          thunk_ConstructTurnEventPacketBase();
          *puVar14 = &PTR_LAB_0065bff0;
        }
        local_4 = CONCAT31(local_4._1_3_,0x1a);
        thunk_FUN_004878a0();
        (**(code **)(*DAT_006a1344 + 0x38))();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
        break;
      }
    }
    else if (uVar25 < 0x6e616d66) {
      if (uVar25 == 0x6e616d65) {
        thunk_FUN_0054cc00();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x6c6f7374) {
        uVar25 = param_2[7];
        sVar10 = thunk_GetActiveNationId();
        local_1c9 = (uVar25 & 0xff) == (int)sVar10;
        InitializeSharedStringRefFromEmpty();
        local_4 = 0x22;
        InitializeSharedStringRefFromEmpty();
        local_4._0_1_ = 0x23;
        InitializeSharedStringRefFromEmpty();
        local_4 = CONCAT31(local_4._1_3_,0x24);
        thunk_LoadUiStringResourceByGroupAndIndex();
        FormatOverlayTerrainLabelText();
        scanBracketExpressions(g_pLocalizationTable,&local_1c8,(char *)local_1d0);
        thunk_FUN_005dea60();
        if ((local_1c9 != '\0') && (g_pLocalizationTable[0x11] == 2)) {
          thunk_FUN_0049e500();
        }
        local_4._0_1_ = 0x23;
        ReleaseSharedStringRefIfNotEmpty();
        local_4 = CONCAT31(local_4._1_3_,0x22);
        ReleaseSharedStringRefIfNotEmpty();
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
        uVar11 = 1;
        break;
      }
    }
    else if (uVar25 < 0x71756975) {
      if ((uVar25 == 0x71756974) || (uVar25 == 0x6e657767)) {
        if (g_pLocalizationTable[0x11] == 2) {
          InitializeSharedStringRefFromEmpty();
          local_4 = 0x16;
          thunk_LoadUiStringResourceByGroupAndIndex();
          thunk_FUN_005dea60();
          local_4 = 0xffffffff;
          ReleaseSharedStringRefIfNotEmpty();
        }
        if ((g_pLocalizationTable[0x11] == 2) || (param_2[6] == 0x6e657767)) {
          thunk_FUN_0049e500();
          uVar11 = 1;
        }
        else {
          PostWmCloseToMainThreadWindow();
          uVar11 = 1;
        }
        break;
      }
    }
    else if (uVar25 < 0x72657070) {
      if (uVar25 == 0x7265706f) {
        uVar25 = param_2[7] & 7;
        if ((((&g_apNationStates)[uVar25] == 0) && (iVar23 = FUN_00405a3d(), param_2[1] == iVar23))
           && (g_pLocalizationTable[0x11] == 1)) {
          bVar5 = true;
        }
        else {
          bVar5 = false;
        }
        if ((uVar25 < 7) &&
           ((bVar5 || (((&g_apNationStates)[uVar25] != 0 &&
                       ((iVar23 = FUN_00405a3d(), param_2[1] == iVar23 ||
                        (cVar7 = (**(code **)(*(int *)(&g_apNationStates)[uVar25] + 0xa0))(),
                        cVar7 != '\0')))))))) {
          uVar11 = param_2[1];
          local_1c4 = *(code **)(local_1d0 + uVar25 * 4 + 0x94);
          pcVar24 = *(char **)(local_1d0 + uVar25 * 4 + 0x78);
          local_1d0 = local_1d0 + uVar25 * 4 + 0x78;
          local_1b8[4] = 0x74696d65;
          local_1a4 = thunk_GetActiveNationId();
          uVar18 = 0xffffffff;
          do {
            pcVar26 = pcVar24;
            if (uVar18 == 0) break;
            uVar18 = uVar18 - 1;
            pcVar26 = pcVar24 + 1;
            cVar7 = *pcVar24;
            pcVar24 = pcVar26;
          } while (cVar7 != '\0');
          local_1b8[1] = 0;
          local_1b8[0] = 9;
          uVar18 = ~uVar18;
          local_1b8[2] = 0;
          local_1b8[3] = 100;
          local_1a0 = CONCAT31(local_1a0._1_3_,(sbyte)uVar25);
          pcVar24 = pcVar26 + -uVar18;
          pcVar26 = local_198;
          for (uVar19 = uVar18 >> 2; uVar19 != 0; uVar19 = uVar19 - 1) {
            *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
            pcVar24 = pcVar24 + 4;
            pcVar26 = pcVar26 + 4;
          }
          for (uVar18 = uVar18 & 3; uVar18 != 0; uVar18 = uVar18 - 1) {
            *pcVar26 = *pcVar24;
            pcVar24 = pcVar24 + 1;
            pcVar26 = pcVar26 + 1;
          }
          uVar18 = 0xffffffff;
          pcVar20 = local_1c4;
          do {
            pcVar24 = (char *)pcVar20;
            if (uVar18 == 0) break;
            uVar18 = uVar18 - 1;
            pcVar24 = (char *)pcVar20 + 1;
            cVar7 = (char)*pcVar20;
            pcVar20 = (code *)pcVar24;
          } while (cVar7 != '\0');
          uVar18 = ~uVar18;
          pcVar24 = pcVar24 + -uVar18;
          pcVar26 = local_177;
          for (uVar19 = uVar18 >> 2; uVar19 != 0; uVar19 = uVar19 - 1) {
            *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
            pcVar24 = pcVar24 + 4;
            pcVar26 = pcVar26 + 4;
          }
          for (uVar18 = uVar18 & 3; uVar18 != 0; uVar18 = uVar18 - 1) {
            *pcVar26 = *pcVar24;
            pcVar24 = pcVar24 + 1;
            pcVar26 = pcVar26 + 1;
          }
          local_19c = uVar11;
          thunk_FUN_005e3d40();
          InitializeSharedStringRefFromEmpty();
          local_4 = 0x17;
          InitializeSharedStringRefFromEmpty();
          local_4._0_1_ = 0x18;
          thunk_LoadUiStringResourceByGroupAndIndex();
          StringSharedRef_AssignFromPtr();
          local_4 = CONCAT31(local_4._1_3_,0x19);
          scanBracketExpressions(g_pLocalizationTable,&local_1c8,local_1d4);
          local_118 = 0x74696d65;
          local_114 = thunk_GetActiveNationId();
          local_124 = 0;
          local_120 = 0;
          local_128 = 0xc;
          local_11c = 0x11c;
          local_10 = 0xff;
          thunk_GetActiveNationId();
          uVar18 = 0xffffffff;
          do {
            pcVar24 = local_1c8;
            if (uVar18 == 0) break;
            uVar18 = uVar18 - 1;
            pcVar24 = local_1c8 + 1;
            cVar7 = *local_1c8;
            local_1c8 = pcVar24;
          } while (cVar7 != '\0');
          uVar18 = ~uVar18;
          pcVar24 = pcVar24 + -uVar18;
          pcVar26 = local_110;
          for (uVar19 = uVar18 >> 2; uVar19 != 0; uVar19 = uVar19 - 1) {
            *(undefined4 *)pcVar26 = *(undefined4 *)pcVar24;
            pcVar24 = pcVar24 + 4;
            pcVar26 = pcVar26 + 4;
          }
          for (uVar18 = uVar18 & 3; uVar18 != 0; uVar18 = uVar18 - 1) {
            *pcVar26 = *pcVar24;
            pcVar24 = pcVar24 + 1;
            pcVar26 = pcVar26 + 1;
          }
          local_128 = 0xc;
          local_f = 0xff;
          local_120 = 0;
          local_10 = -1 - ('\x01' << (sbyte)uVar25);
          thunk_FUN_005e3d40();
          local_4._0_1_ = 0x18;
          ReleaseSharedStringRefIfNotEmpty();
          local_4 = CONCAT31(local_4._1_3_,0x17);
          ReleaseSharedStringRefIfNotEmpty();
          local_4 = 0xffffffff;
          ReleaseSharedStringRefIfNotEmpty();
          uVar11 = 1;
        }
        else {
          local_1b8[4] = 0x74696d65;
          local_1a4 = thunk_GetActiveNationId();
          local_1b8[2] = param_2[1];
          local_1b8[1] = 0;
          local_1b8[0] = 0x1f;
          local_1b8[3] = 0x20;
          local_1a0 = 0x666f6666;
          local_19c = 0x29;
          thunk_FUN_005e3d40();
          uVar11 = 1;
        }
        break;
      }
      if ((uVar25 == 0x72656765) && (g_pLocalizationTable[0x11] == 2)) {
        (**(code **)(*g_pStrategicMapViewSystem + 0x78))();
        uVar11 = 1;
        break;
      }
    }
    else {
      if (uVar25 == 0x73617665) {
        param_1[0xf4] = *(code *)(param_2 + 7);
        thunk_SaveGameWithModeAndOptionalLabel();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x74726164) {
        sVar10 = thunk_GetActiveNationId();
        (**(code **)(*(int *)(&g_apNationStates)[sVar10] + 0x48))();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x74726173) {
        sVar10 = thunk_GetActiveNationId();
        (**(code **)(*(int *)(&g_apNationStates)[sVar10] + 0xd0))();
        uVar11 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0x20:
    thunk_QueueInterNationEventRecordDeduped
              (g_pInterNationEventQueueManager,(int)*(short *)(param_2 + 6),
               (int)*(char *)((int)param_2 + 0x1a),(int)*(char *)((int)param_2 + 0x1b),'\x01');
    uVar11 = 1;
    break;
  case 0x21:
    thunk_QueueInterNationEventType0FWithBitmaskMerge
              (g_pInterNationEventQueueManager,(int)*(char *)(param_2 + 6),
               (int)*(char *)((int)param_2 + 0x19),(int)*(char *)((int)param_2 + 0x1a),'\x01');
    uVar11 = 1;
    break;
  case 0x22:
    thunk_QueueInterNationEventType11
              (g_pInterNationEventQueueManager,(int)*(char *)(param_2 + 6),
               (int)*(short *)((int)param_2 + 0x1a),'\x01');
    uVar11 = 1;
    break;
  case 0x23:
    sVar10 = *(short *)(param_2 + 7);
    iVar23 = g_pGlobalMapState[3];
    *(undefined1 *)(iVar23 + 4 + sVar10 * 0x24) = *(undefined1 *)(param_2 + 9);
    iVar23 = iVar23 + sVar10 * 0x24;
    *(undefined1 *)(iVar23 + 5) = *(undefined1 *)((int)param_2 + 0x25);
    *(undefined1 *)(iVar23 + 6) = *(undefined1 *)((int)param_2 + 0x26);
    *(undefined1 *)(iVar23 + 0xc) = *(undefined1 *)(param_2 + 0xb);
    *(byte *)(iVar23 + 0xd) = *(byte *)(iVar23 + 0xd) | *(byte *)((int)param_2 + 0x2d);
    *(undefined1 *)(iVar23 + 0x18) = *(undefined1 *)(param_2 + 0xe);
    *(undefined2 *)(iVar23 + 0x1c) = *(undefined2 *)(param_2 + 0xf);
    uVar11 = 1;
    break;
  case 0x24:
    sVar10 = *(short *)(param_2 + 7);
    iVar31 = 10;
    iVar23 = g_pGlobalMapState[4];
    *(undefined1 *)(iVar23 + sVar10 * 0xa8) = *(undefined1 *)(param_2 + 8);
    iVar23 = iVar23 + sVar10 * 0xa8;
    *(undefined1 *)(iVar23 + 2) = *(undefined1 *)((int)param_2 + 0x22);
    *(undefined1 *)(iVar23 + 3) = *(undefined1 *)((int)param_2 + 0x23);
    *(undefined2 *)(iVar23 + 6) = *(undefined2 *)((int)param_2 + 0x26);
    puVar13 = (undefined2 *)(iVar23 + 0x82);
    puVar16 = (undefined2 *)((int)param_2 + 0xa2);
    do {
      uVar3 = *puVar16;
      puVar16 = puVar16 + 1;
      *puVar13 = uVar3;
      puVar13 = puVar13 + 1;
      iVar31 = iVar31 + -1;
    } while (iVar31 != 0);
    *(undefined1 *)(iVar23 + 0xa1) = *(undefined1 *)((int)param_2 + 0xc1);
    *(undefined1 *)(iVar23 + 0xa2) = *(undefined1 *)((int)param_2 + 0xc2);
    uVar11 = 1;
    break;
  case 0x25:
    iVar23 = 0;
    piVar15 = param_2 + 6;
    local_1d4 = (char *)0x0;
    pcVar20 = param_1 + 0xbc;
    iVar31 = 7;
    do {
      if (*piVar15 != 0x756e6b6e) {
        *(int *)pcVar20 = *piVar15;
      }
      if (*(int *)pcVar20 == 0x72656479) {
        iVar23 = iVar23 + 1;
      }
      else if (*(int *)pcVar20 == 0x62757379) {
        local_1d4 = (char *)((int)local_1d4 + 1);
      }
      piVar15 = piVar15 + 1;
      pcVar20 = pcVar20 + 4;
      iVar31 = iVar31 + -1;
    } while (iVar31 != 0);
    if ((0 < iVar23) && (local_1d4 == (char *)0x1)) {
      sVar10 = thunk_GetActiveNationId();
      iVar23 = (int)sVar10;
      if (iVar23 == -1) {
        iVar31 = FUN_00405a3d();
        iVar23 = 0;
        piVar15 = (int *)(g_pGameFlowState + 0x48);
        do {
          if (*piVar15 == iVar31) goto LAB_0054833b;
          iVar23 = iVar23 + 1;
          piVar15 = piVar15 + 1;
        } while (iVar23 < 7);
        iVar23 = -1;
      }
LAB_0054833b:
      if ((*(int *)(param_1 + iVar23 * 4 + 0xbc) == 0x62757379) && (param_1[0xf4] != (code)0x0)) {
        (**(code **)(*g_pSfxPlaybackSystem + 0xb8))();
        uVar11 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0x26:
    puVar14 = param_2 + 6;
    pDVar32 = g_pDiplomacyTurnStateManager;
    for (iVar23 = 0xc0; pDVar32 = (DiplomacyTurnStateManager *)pDVar32->relationCodeMatrix17x17,
        iVar23 != 0; iVar23 = iVar23 + -1) {
      *(undefined4 *)pDVar32 = *puVar14;
      puVar14 = puVar14 + 1;
    }
    puVar14 = param_2 + 0xc6;
    pbVar33 = g_pDiplomacyTurnStateManager->pendingPolicyCodeMatrix17x17;
    for (iVar23 = 0x60; iVar23 != 0; iVar23 = iVar23 + -1) {
      *(undefined4 *)pbVar33 = *puVar14;
      puVar14 = puVar14 + 1;
      pbVar33 = pbVar33 + 4;
    }
    puVar14 = param_2 + 0x126;
    puVar27 = (undefined4 *)&g_pDiplomacyTurnStateManager->field_0x484;
    for (iVar23 = 0xc0; iVar23 != 0; iVar23 = iVar23 + -1) {
      *puVar27 = *puVar14;
      puVar14 = puVar14 + 1;
      puVar27 = puVar27 + 1;
    }
    uVar11 = param_2[0x1e6];
    pDVar32 = g_pDiplomacyTurnStateManager;
    pDVar32->selectedSourceNationSlot = (short)uVar11;
    pDVar6 = g_pDiplomacyTurnStateManager;
    pDVar32->selectedTargetNationSlot = (short)((uint)uVar11 >> 0x10);
    uVar11 = param_2[0x1e7];
    pDVar32 = g_pDiplomacyTurnStateManager;
    pDVar32->selectionFlagsA = (short)uVar11;
    pDVar32->selectionFlagsB = (short)((uint)uVar11 >> 0x10);
    pDVar6->selectionFlagsC = *(short *)(param_2 + 0x1e8);
    uVar11 = 1;
    puVar14 = param_2 + 0x1e9;
    puVar27 = (undefined4 *)&g_pDiplomacyTurnStateManager->field_0x1824;
    for (iVar23 = 0x1c; iVar23 != 0; iVar23 = iVar23 + -1) {
      *puVar27 = *puVar14;
      puVar14 = puVar14 + 1;
      puVar27 = puVar27 + 1;
    }
    break;
  case 0x27:
    (**(code **)(*(int *)(&g_pTerrainTypeDescriptorTable)[param_2[6]] + 0x4c))();
    uVar11 = 1;
    break;
  case 0x28:
  case 0x2e:
  case 0x2f:
  case 0x30:
  case 0x31:
  case 0x32:
    DAT_00695278 = 0x6e657458;
    hMem = GlobalAlloc(2,param_2[3]);
    GlobalLock(hMem);
    FUN_005e8420();
    GlobalUnlock(hMem);
    local_1c4 = (code *)AllocateWithFallbackHandler();
    local_4 = 0x15;
    if (local_1c4 == (code *)0x0) {
      piVar15 = (int *)0x0;
    }
    else {
      piVar15 = (int *)thunk_FUN_004895e0();
    }
    local_4 = 0xffffffff;
    thunk_FUN_00489660();
    HandleTurnEventCodes28_2E_2F_30_31_32();
    (**(code **)(*piVar15 + 0x1c))();
    DAT_00695278 = 0xffffffff;
    uVar11 = 1;
    break;
  case 0x29:
    (**(code **)(*DAT_006a475c + 0xc))();
    thunk_FUN_005a53e0();
    uVar25 = param_2[6];
    if (uVar25 < 0x64696768) {
      if (uVar25 == 0x64696767) {
        thunk_HandleTacticalCommandTag_digg();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x6465706c) {
        thunk_HandleTacticalCommandTag_depl();
        uVar11 = 1;
        break;
      }
    }
    else if (uVar25 < 0x6d6f7666) {
      if (uVar25 == 0x6d6f7665) {
        thunk_MoveTacticalUnitBetweenTiles();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x6d696e65) {
        thunk_HandleTacticalCommandTag_mine();
        uVar11 = 1;
        break;
      }
    }
    else {
      if (uVar25 == 0x72616c79) {
        thunk_HandleTacticalCommandTag_raly();
        uVar11 = 1;
        break;
      }
      if (uVar25 == 0x73656c65) {
        thunk_SetCurrentTacticalUnitSelection();
        uVar11 = 1;
        break;
      }
    }
    goto LAB_005485d8;
  case 0x2a:
    (**(code **)(*DAT_006a475c + 0xc))();
    thunk_FUN_005a53e0();
    thunk_FUN_005a53e0();
    if (param_2[6] == 0x66697265) {
      thunk_FUN_005a24a0();
      uVar11 = 1;
      break;
    }
    goto LAB_005485d8;
  case 0x2b:
    DAT_006a3d64 = DAT_006a3d64 | (int)*(char *)((int)param_2 + 0x19);
    if (*(char *)(param_2 + 6) != '\0') {
      local_1b8[4] = 0x74696d65;
      local_1a4 = thunk_GetActiveNationId();
      local_1b8[0] = 0x2b;
      local_1b8[1] = 0;
      local_1b8[2] = 0;
      local_1a0 = local_1a0 & 0xffffff00;
      local_1b8[3] = 0x1c;
      uVar8 = thunk_GetActiveNationId();
      local_1b8[2] = param_2[1];
      local_1a0._0_2_ = CONCAT11(uVar8,(undefined1)local_1a0);
      thunk_FUN_005e3d40();
    }
    goto LAB_005485d8;
  case 0x2c:
    iVar23 = (int)*(short *)(param_2 + 7);
    sVar10 = thunk_GetActiveNationId();
    if (iVar23 != sVar10) {
      *(undefined4 *)((&g_apNationStates)[iVar23] + 0x910) = param_2[8];
      *(undefined4 *)((&g_apNationStates)[iVar23] + 0x914) = param_2[9];
      if ((&g_apNationStates)[iVar23] == 0) {
        iVar31 = 0;
      }
      else {
        iVar31 = *(int *)((&g_apNationStates)[iVar23] + 0x894);
      }
      puVar13 = (undefined2 *)(iVar31 + 0xe);
      puVar16 = (undefined2 *)((int)param_2 + 0x2e);
      iVar22 = 0x1e;
      do {
        uVar3 = *puVar16;
        puVar16 = puVar16 + 1;
        *puVar13 = uVar3;
        puVar13 = puVar13 + 1;
        iVar22 = iVar22 + -1;
      } while (iVar22 != 0);
      puVar13 = (undefined2 *)(iVar31 + 0x4a);
      puVar16 = (undefined2 *)((int)param_2 + 0x6a);
      iVar22 = 9;
      do {
        uVar3 = *puVar16;
        puVar16 = puVar16 + 1;
        *puVar13 = uVar3;
        puVar13 = puVar13 + 1;
        iVar22 = iVar22 + -1;
      } while (iVar22 != 0);
      puVar13 = (undefined2 *)(iVar31 + 0x5c);
      puVar14 = param_2 + 0x1f;
      iVar22 = 0xe;
      do {
        uVar3 = *(undefined2 *)puVar14;
        puVar14 = (undefined4 *)((int)puVar14 + 2);
        *puVar13 = uVar3;
        puVar13 = puVar13 + 1;
        iVar22 = iVar22 + -1;
      } while (iVar22 != 0);
      (**(code **)(*(int *)(&g_apNationStates)[iVar23] + 0x164))();
      puVar13 = (undefined2 *)(iVar31 + 0xb6);
      *(undefined4 *)(iVar31 + 0x78) = param_2[0x26];
      *(undefined2 *)(iVar31 + 0xb4) = *(undefined2 *)(param_2 + 0x27);
      puVar16 = (undefined2 *)((int)param_2 + 0x9e);
      iVar23 = 0x17;
      puVar17 = puVar13;
      do {
        uVar3 = *puVar16;
        puVar16 = puVar16 + 1;
        *puVar17 = uVar3;
        puVar17 = puVar17 + 1;
        iVar23 = iVar23 + -1;
      } while (iVar23 != 0);
      puVar16 = (undefined2 *)(iVar31 + 0x1dc);
      puVar14 = param_2 + 0x33;
      iVar23 = 0x10;
      do {
        uVar3 = *(undefined2 *)puVar14;
        puVar14 = (undefined4 *)((int)puVar14 + 2);
        *puVar16 = uVar3;
        puVar16 = puVar16 + 1;
        iVar23 = iVar23 + -1;
      } while (iVar23 != 0);
      puVar16 = (undefined2 *)(iVar31 + 0x1fc);
      puVar14 = param_2 + 0x3b;
      iVar23 = 0x10;
      do {
        uVar3 = *(undefined2 *)puVar14;
        puVar14 = (undefined4 *)((int)puVar14 + 2);
        *puVar16 = uVar3;
        puVar16 = puVar16 + 1;
        iVar23 = iVar23 + -1;
      } while (iVar23 != 0);
      *(undefined2 *)(iVar31 + 0x26c) = *(undefined2 *)(param_2 + 0x43);
      puVar16 = (undefined2 *)((int)param_2 + 0x9e);
      iVar23 = 0x17;
      do {
        uVar3 = *puVar16;
        puVar16 = puVar16 + 1;
        *puVar13 = uVar3;
        puVar13 = puVar13 + 1;
        iVar23 = iVar23 + -1;
      } while (iVar23 != 0);
      piVar15 = (int *)(iVar31 + 0xe4);
      puVar14 = param_2 + 0x44;
      iVar23 = 0x17;
      do {
        if (*piVar15 != 0) {
          *(undefined4 *)(*piVar15 + 0x44) = *puVar14;
        }
        puVar14 = puVar14 + 1;
        piVar15 = piVar15 + 1;
        iVar23 = iVar23 + -1;
      } while (iVar23 != 0);
      iVar23 = *(int *)(iVar31 + 0x1d8);
      *(undefined2 *)(iVar23 + 8) = *(undefined2 *)(param_2 + 0x5b);
      *(undefined4 *)(iVar23 + 0xc) = param_2[0x5c];
      *(undefined2 *)(iVar23 + 0x1c) = *(undefined2 *)(param_2 + 0x5d);
      *(undefined2 *)(iVar23 + 0x1e) = *(undefined2 *)((int)param_2 + 0x176);
      *(undefined2 *)(iVar23 + 0x20) = *(undefined2 *)(param_2 + 0x5e);
      *(undefined2 *)(*(int *)(iVar23 + 0x10) + 4) = *(undefined2 *)((int)param_2 + 0x17a);
      *(undefined2 *)(*(int *)(iVar23 + 0x10) + 6) = *(undefined2 *)(param_2 + 0x5f);
      *(undefined2 *)(*(int *)(iVar23 + 0x10) + 8) = *(undefined2 *)((int)param_2 + 0x17e);
      *(undefined2 *)(*(int *)(iVar23 + 0x14) + 4) = *(undefined2 *)(param_2 + 0x60);
      *(undefined2 *)(*(int *)(iVar23 + 0x14) + 6) = *(undefined2 *)((int)param_2 + 0x182);
      *(undefined2 *)(*(int *)(iVar23 + 0x14) + 8) = *(undefined2 *)(param_2 + 0x61);
      *(undefined2 *)(*(int *)(iVar23 + 0x18) + 4) = *(undefined2 *)((int)param_2 + 0x186);
      *(undefined2 *)(*(int *)(iVar23 + 0x18) + 6) = *(undefined2 *)(param_2 + 0x62);
      *(undefined2 *)(*(int *)(iVar23 + 0x18) + 8) = *(undefined2 *)((int)param_2 + 0x18a);
      uVar11 = 1;
      break;
    }
LAB_005485d8:
    uVar11 = 1;
    break;
  case 0x2d:
    iVar23 = 0x17;
    puVar13 = (undefined2 *)((&DAT_006a4280)[*(short *)(param_2 + 7)] + 0x14);
    puVar16 = (undefined2 *)((int)param_2 + 0x1e);
    do {
      uVar3 = *puVar16;
      puVar16 = puVar16 + 1;
      *puVar13 = uVar3;
      puVar13 = puVar13 + 1;
      iVar23 = iVar23 + -1;
    } while (iVar23 != 0);
    uVar11 = 1;
  }
  *unaff_FS_OFFSET = local_c;
  return uVar11;
}

