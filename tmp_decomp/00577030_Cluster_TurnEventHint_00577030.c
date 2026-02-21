
void __fastcall Cluster_TurnEventHint_00577030(int *param_1)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  int *piVar5;
  int iVar6;
  undefined4 *unaff_FS_OFFSET;
  bool bVar7;
  code *pcVar8;
  code *pcVar9;
  undefined4 uVar10;
  code *pcVar11;
  int aiStack_70 [2];
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  uStack_c = *unaff_FS_OFFSET;
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_0063697a;
  *unaff_FS_OFFSET = &uStack_c;
  thunk_FUN_0048ab70();
  thunk_FUN_005dff20();
  *(undefined2 *)(g_pLocalizationTable + 0x114) = 0;
  if (g_pGlobalMapState == 0) {
    iVar2 = GenerateThreadLocalRandom15();
    *(short *)((int)param_1 + 0x9a) = (short)(iVar2 % 7);
    thunk_GenerateMappedFlavorTextByCurrentContextNation(param_1 + 0x25);
    *(undefined1 *)(param_1 + 0x26) = 0;
  }
  else {
    StringShared__AssignFromPtr(param_1 + 0x25,(int *)(g_pGlobalMapState + 0x1c));
    *(undefined1 *)(param_1 + 0x26) = *(undefined1 *)(g_pGlobalMapState + 0x20);
    bVar7 = DAT_00698ab0 == -1;
    *(short *)((int)param_1 + 0x9a) = DAT_00698ab0;
    if (bVar7) {
      iVar2 = GenerateThreadLocalRandom15();
      *(short *)((int)param_1 + 0x9a) = (short)(iVar2 % 7);
    }
    piVar3 = (int *)(**(code **)(*param_1 + 0x94))();
    (**(code **)(*piVar3 + 0xc))();
    piVar3[0x1b] = (int)*(short *)((int)param_1 + 0x9a);
  }
  thunk_FUN_005c4310();
  pcVar8 = *(code **)(*param_1 + 0x94);
  piVar3 = (int *)(*pcVar8)();
  (**(code **)(*piVar3 + 0xc))();
  *(undefined2 *)(piVar3 + 0x27) = 0xc;
  DAT_006a43f0 = 0;
  RebuildGlobalOrderManagersAndCapabilityState();
  g_pCursorControlPanel = (int *)(*pcVar8)();
  (**(code **)(*g_pCursorControlPanel + 0xc))();
  (**(code **)(*g_pCursorControlPanel + 0x1e0))();
  (**(code **)(*g_pCursorControlPanel + 0x204))();
  (**(code **)(*g_pCursorControlPanel + 0x1c4))();
  thunk_FUN_005c4ab0();
  thunk_FUN_005c4ab0();
  thunk_FUN_005c4ab0();
  thunk_FUN_005c46b0();
  thunk_FUN_005c46b0();
  if (*(int *)(g_pLocalizationTable + 0x44) == 0) {
    thunk_FUN_005c46b0();
  }
  else {
    thunk_FUN_005c46b0();
  }
  thunk_FUN_005c46b0();
  thunk_FUN_005c46b0();
  thunk_FUN_005c46b0();
  thunk_FUN_005c46b0();
  thunk_FUN_005c46b0();
  thunk_FUN_005c46b0();
  thunk_FUN_005c46b0();
  piVar3 = (int *)(*pcVar8)();
  iVar2 = *piVar3;
  (**(code **)(iVar2 + 0xc))();
  aiStack_70[1] = 0x57730e;
  thunk_ApplyUiTextStyleAndThemeFlags(piVar3,0,0xe,0x2b6a,0x2b6c);
  (**(code **)(iVar2 + 0x1cc))();
  piVar3 = (int *)(*pcVar8)();
  (**(code **)(*piVar3 + 0xc))();
  piVar3[0x1a] = (int)*(short *)((int)param_1 + 0x9a);
  aiStack_70[1] = 0x577345;
  puVar4 = (undefined4 *)AllocateWithFallbackHandler();
  if (puVar4 == (undefined4 *)0x0) {
    puVar4 = (undefined4 *)0x0;
  }
  else {
    thunk_ConstructTurnEventPacketBase();
    *puVar4 = &PTR_LAB_00661b10;
  }
  aiStack_70[1] = 0;
  aiStack_70[0] = 0;
  thunk_FUN_004878a0();
  puVar4[6] = param_1;
  *(undefined1 *)(puVar4 + 7) = 1;
  aiStack_70[1] = 0x57739f;
  (**(code **)(*DAT_006a1344 + 0x38))();
  aiStack_70[1] = 0;
  aiStack_70[0] = 1;
  (**(code **)(*g_pCursorControlPanel + 0x1c4))();
  piVar3 = (int *)(*pcVar8)();
  (**(code **)(*piVar3 + 0xc))();
  piVar3[0x18] = *(int *)(g_pStrategicMapViewSystem + 0x680);
  sVar1 = *(short *)((int)param_1 + 0x9a);
  piVar3[0x19] = (int)sVar1 * piVar3[0xd];
  piVar3[0x1a] = 0;
  piVar3[0x1b] = (sVar1 + 1) * piVar3[0xd];
  piVar3[0x1c] = piVar3[0xe];
  if (*(int *)(g_pLocalizationTable + 0x44) == 0) {
    *(char *)(g_pLocalizationTable + 0x68) = (char)*(undefined2 *)(g_pLocalizationTable + 0x62);
    InitializeSharedStringRefFromEmpty();
    thunk_GenerateMappedFlavorTextByCurrentContextNation(&DAT_006a4220);
    thunk_FUN_005e01a0();
    piVar3 = (int *)thunk_NormalizeRuntimeCredentialNameToken();
    StringShared__AssignFromPtr(&DAT_006a4220,piVar3);
    ReleaseSharedStringRefIfNotEmpty();
  }
  else {
    piVar3 = (int *)thunk_NormalizeRuntimeCredentialNameToken();
    StringShared__AssignFromPtr(&DAT_006a4220,piVar3);
  }
  ReleaseSharedStringRefIfNotEmpty();
  thunk_FUN_005c4310();
  piVar3 = (int *)(*pcVar8)();
  (**(code **)(*piVar3 + 0xc))();
  thunk_SetSelectedTextOptionByTag
            (piVar3,*(short *)(g_pLocalizationTable + 0x5e) + 0x64696630,false);
  *(undefined2 *)(piVar3 + 0x24) = 0x2b6b;
  piVar5 = (int *)(*pcVar8)();
  iVar2 = *piVar5;
  (**(code **)(iVar2 + 0xc))();
  thunk_ApplyUiTextStyleAndThemeFlags(piVar5,0,0xe,0x2b6a,0x2b6c);
  InitializeSharedStringRefFromEmpty();
  thunk_LoadUiStringResourceByGroupAndIndex();
  (**(code **)(iVar2 + 0x1c8))();
  piVar5 = (int *)(*pcVar8)();
  aiStack_70[0] = *piVar5;
  (**(code **)(aiStack_70[0] + 0xc))();
  thunk_ApplyUiTextStyleAndThemeFlags(piVar5,0,0xe,0x2b6a,0x2b6c);
  thunk_LoadUiStringResourceByGroupAndIndex();
  pcVar11 = (code *)&stack0xffffffa8;
  (**(code **)(aiStack_70[0] + 0x1c8))();
  piVar5 = (int *)(*pcVar8)();
  iVar2 = *piVar5;
  (**(code **)(iVar2 + 0xc))();
  thunk_SetSelectedTextOptionByTag
            (piVar5,(-(uint)(*(short *)(g_pLocalizationTable + 0x62) != 0) & 0xf6080510) +
                    0x72616e64,false);
  pcVar8 = *(code **)(iVar2 + 0x94);
  *(undefined2 *)(piVar5 + 0x24) = 0x2b6b;
  piVar5 = (int *)(*pcVar8)();
  (**(code **)(*piVar5 + 0xc))();
  thunk_ApplyUiTextStyleAndThemeFlags(piVar5,0,0xc,0x2b6b,0x2b6c);
  uVar10 = 0;
  pcVar9 = (code *)0x1;
  (**(code **)(*piVar5 + 0x1c4))();
  thunk_LoadUiStringResourceByGroupAndIndex(aiStack_70,0x2758,4);
  (**(code **)(*piVar5 + 0x1c8))(aiStack_70,0);
  piVar5[0xf] = 0x68697374;
  piVar5 = (int *)(*pcVar11)(0x72616e64);
  iVar2 = *piVar5;
  (**(code **)(iVar2 + 0xc))();
  thunk_ApplyUiTextStyleAndThemeFlags(piVar5,0,0xc,0x2b6b,0x2b6c);
  (**(code **)(iVar2 + 0x1c4))(1,0);
  thunk_LoadUiStringResourceByGroupAndIndex(&stack0xffffff7c,0x2758,5);
  (**(code **)(iVar2 + 0x1c8))(&stack0xffffff7c,0);
  iVar2 = *piVar3;
  piVar5[0xf] = 0x72616e64;
  iVar6 = 0;
  pcVar8 = *(code **)(iVar2 + 0x94);
  do {
    piVar3 = (int *)(*pcVar8)(iVar6 + 0x64696630);
    (**(code **)(*piVar3 + 0xc))();
    thunk_ApplyUiTextStyleAndThemeFlags(piVar3,0,0xc,0x2b6b,0x2b6c);
    (**(code **)(*piVar3 + 0x1c4))(1,0);
    thunk_LoadUiStringResourceByGroupAndIndex(&stack0xffffff68,0x2737,iVar6 + 0xe);
    (**(code **)(*piVar3 + 0x1c8))(&stack0xffffff68,0);
    piVar3[0xf] = iVar6;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 5);
  if (((char)param_1[0x29] == '\0') && (*(int *)(g_pLocalizationTable + 0x44) == 0)) {
    piVar3 = (int *)(*pcVar9)(0x636f756e);
    (**(code **)(*piVar3 + 0xc))();
  }
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = uVar10;
  return;
}

