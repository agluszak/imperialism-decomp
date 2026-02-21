// 0x00542b10 FUN_00542b10

void __fastcall FUN_00542b10(int param_1)

{
  undefined4 unaff_ESI;
  undefined4 *unaff_FS_OFFSET;
  int local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00634898;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  local_10 = param_1;
  StringSharedRef_AssignFromPtr(param_1 + 0xb0);
  local_4 = 0;
  thunk_FUN_005e0260(&local_10,s_PlayerName_0069801c);
  local_4 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  (**(code **)(*DAT_006a1344 + 0xa4))(param_1,0);
  g_pGameFlowState = 0;
  (**(code **)(*DAT_006a6014 + 0x1c))();
  DAT_006a6014 = (int *)0x0;
  *(undefined4 *)(param_1 + 0x44) = 0;
  thunk_FUN_0048a1b0();
  *unaff_FS_OFFSET = unaff_ESI;
  return;
}




// 0x00544cd0 FUN_00544cd0

void __thiscall FUN_00544cd0(int param_1,undefined4 *param_2)

{
  ushort *puVar1;
  ushort uVar2;
  ushort *puVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  
  switch(*(undefined1 *)(param_1 + 0x21)) {
  case 0:
    uVar4 = *(int *)(param_1 + 0xc) - 0x24;
    puVar7 = (undefined4 *)(param_1 + 0x24);
    for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *param_2 = *puVar7;
      puVar7 = puVar7 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined1 *)param_2 = *(undefined1 *)puVar7;
      puVar7 = (undefined4 *)((int)puVar7 + 1);
      param_2 = (undefined4 *)((int)param_2 + 1);
    }
    return;
  case 1:
    iVar6 = (*(int *)(param_1 + 0xc) + -0x24) / 3;
    puVar3 = (ushort *)(param_1 + 0x24);
    if (iVar6 != 0) {
      do {
        uVar2 = *puVar3;
        puVar1 = puVar3 + 1;
        puVar3 = (ushort *)((int)puVar3 + 3);
        iVar6 = iVar6 + -1;
        *(char *)((uint)uVar2 + (int)param_2) = (char)*puVar1;
      } while (iVar6 != 0);
      return;
    }
    break;
  case 2:
    puVar3 = (ushort *)(param_1 + 0x24);
    iVar6 = *(int *)(param_1 + 0xc) + -0x24;
    iVar6 = (int)(iVar6 + (iVar6 >> 0x1f & 3U)) >> 2;
    if (iVar6 != 0) {
      do {
        uVar2 = *puVar3;
        puVar1 = puVar3 + 1;
        puVar3 = puVar3 + 2;
        iVar6 = iVar6 + -1;
        *(ushort *)((int)param_2 + (uint)uVar2 * 2) = *puVar1;
      } while (iVar6 != 0);
      return;
    }
    break;
  case 3:
    puVar3 = (ushort *)(param_1 + 0x24);
    for (iVar6 = (*(int *)(param_1 + 0xc) + -0x24) / 6; iVar6 != 0; iVar6 = iVar6 + -1) {
      uVar2 = *puVar3;
      puVar1 = puVar3 + 1;
      puVar3 = puVar3 + 3;
      param_2[uVar2] = *(undefined4 *)puVar1;
    }
  }
  return;
}




// 0x00544e70 FUN_00544e70

undefined4 __thiscall FUN_00544e70(int param_1,int *param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int unaff_ESI;
  undefined4 unaff_retaddr;
  
  piVar2 = param_2;
  *(int **)(param_1 + 0x40) = param_2;
  cVar1 = thunk_FUN_005e39a0(param_2);
  if (cVar1 == '\0') {
    return 0;
  }
  thunk_FUN_005e0290(&param_2,s_DefaultProtocol_0069802c,0x70726f30);
  piVar2 = (int *)(**(code **)(*piVar2 + 0x94))(0x70726f74);
  iVar3 = *piVar2;
  (**(code **)(iVar3 + 0xc))();
  iVar3 = (**(code **)(iVar3 + 0x94))(unaff_retaddr);
  if (iVar3 != 0) {
    thunk_SetSelectedTextOptionByTag(piVar2,unaff_ESI,true);
    return 1;
  }
  thunk_SetSelectedTextOptionByTag(piVar2,0x70726f30,true);
  return 1;
}




// 0x00545110 FUN_00545110

undefined1 __thiscall FUN_00545110(int param_1,int *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined1 uVar3;
  int *piVar4;
  undefined4 unaff_EDI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00634998;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  thunk_FUN_005e34b0();
  *(int **)(param_1 + 0x40) = param_2;
  InitializeSharedStringRefFromEmpty();
  local_4 = 0;
  pcVar1 = *(code **)(*param_2 + 0x94);
  piVar4 = (int *)(*pcVar1)(0x6e616d65);
  iVar2 = *piVar4;
  (**(code **)(iVar2 + 0xc))();
  piVar4 = (int *)thunk_FUN_00508c50(&stack0x00000000,param_1 + 0xb0);
  puStack_8._0_1_ = 1;
  StringShared__AssignFromPtr(&stack0xffffffe8,piVar4);
  puStack_8 = (undefined1 *)((uint)puStack_8._1_3_ << 8);
  ReleaseSharedStringRefIfNotEmpty();
  (**(code **)(iVar2 + 0x1e0))(&stack0xffffffe8,0);
  ConstructSharedStringFromCStrOrResourceId(&DAT_006a13a0);
  StringShared__AssignFromPtr(&stack0xffffffe0,(int *)&puStack_8);
  ReleaseSharedStringRefIfNotEmpty();
  piVar4 = (int *)(*pcVar1)(0x70617373);
  iVar2 = *piVar4;
  (**(code **)(iVar2 + 0xc))();
  (**(code **)(iVar2 + 0x1e0))(&stack0xffffffdc,0);
  uVar3 = thunk_FUN_005e3c00();
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = unaff_EDI;
  return uVar3;
}




// 0x00549c60 FUN_00549c60

void FUN_00549c60(int *param_1,int *param_2,short param_3)

{
  int *piVar1;
  code *pcVar2;
  int iVar3;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  int local_1c [5];
  undefined1 local_8;
  undefined2 local_4;
  
  local_1c[4] = 0x74696d65;
  local_8 = thunk_GetActiveNationId();
  local_1c[1] = 0;
  local_1c[3] = 0x1c;
  iVar3 = (int)param_3;
  local_4 = *(undefined2 *)(g_pGameFlowState + 0xf0);
  if ((iVar3 == -2) || (iVar3 == -3)) {
    local_1c[2] = 0;
  }
  else if (iVar3 == -1) {
    local_1c[2] = 0xffffffff;
  }
  else {
    local_1c[2] = *(undefined4 *)(g_pGameFlowState + 0x48 + iVar3 * 4);
  }
  iVar3 = *param_1;
  local_1c[0] = (int)(short)param_2;
  (**(code **)(iVar3 + 0x78))(local_1c,0x1c);
  switch((int)(short)param_2) {
  case 0x28:
    (**(code **)(*param_2 + 0x14))(param_1);
    return;
  case 0x2e:
    SerializeNavyOrderListsByNation(param_1,param_2);
    return;
  case 0x2f:
    thunk_FUN_0054a500(param_1,param_2);
    return;
  case 0x30:
    thunk_FUN_0054a5e0(param_1,param_2);
    return;
  case 0x31:
    (**(code **)(iVar3 + 0x8c))(*param_2);
    if (*param_2 != 0x73746172) {
      (**(code **)(*(int *)param_2[1] + 0x14))(param_1);
      return;
    }
    piVar1 = (int *)param_2[1];
    pcVar2 = *(code **)(*piVar1 + 0xc);
    (*pcVar2)();
    (**(code **)(iVar3 + 0x8c))(piVar1[1]);
    if (piVar1[1] == 0x6c616e64) {
      (*pcVar2)();
      pcVar2 = *(code **)(iVar3 + 0x88);
      (*pcVar2)(CONCAT22(extraout_var_00,(short)piVar1[2]));
      (*pcVar2)(CONCAT22(extraout_var,*(undefined2 *)((int)piVar1 + 10)));
      return;
    }
    break;
  case 0x32:
    (**(code **)(g_pNationInteractionStateManager->vftable + 0x14))(param_1);
  }
  return;
}




// 0x0054a500 FUN_0054a500

void FUN_0054a500(int *param_1,int param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  int *piVar3;
  int iVar4;
  
  iVar4 = *param_1;
  pcVar1 = *(code **)(iVar4 + 0x7c);
  (*pcVar1)((char)param_2 + 'a');
  if ((&g_pTerrainTypeDescriptorTable)[param_2] == 0) {
    (**(code **)(iVar4 + 0x88))(0);
  }
  else {
    uVar2 = (**(code **)(**(int **)((&g_pTerrainTypeDescriptorTable)[param_2] + 0x44) + 0x48))();
    (**(code **)(iVar4 + 0x88))(uVar2);
    piVar3 = (int *)thunk_FUN_00487ef0();
    iVar4 = thunk_FUN_00487f20();
    if (iVar4 != 0) {
      do {
        (**(code **)(*piVar3 + 0x14))(param_1);
        piVar3 = (int *)thunk_FUN_00487f40();
        iVar4 = thunk_FUN_00487f20();
      } while (iVar4 != 0);
      (*pcVar1)(0x2e);
      return;
    }
  }
  (*pcVar1)(0x2e);
  return;
}




// 0x0054a5e0 FUN_0054a5e0

void FUN_0054a5e0(int *param_1,int param_2)

{
  bool bVar1;
  undefined4 uVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  
  iVar6 = 0;
  piVar5 = &g_apNationStates;
  do {
    if ((param_2 == -1) || (param_2 == iVar6)) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
    if ((*piVar5 == 0) || (!bVar1)) {
      (**(code **)(*param_1 + 0x88))(0);
    }
    else {
      iVar4 = *param_1;
      uVar2 = (**(code **)(**(int **)(*piVar5 + 0x89c) + 0x48))();
      (**(code **)(iVar4 + 0x88))(uVar2);
      piVar3 = (int *)thunk_FUN_00487ef0();
      iVar4 = thunk_FUN_00487f20();
      while (iVar4 != 0) {
        (**(code **)(*piVar3 + 0x14))(param_1);
        piVar3 = (int *)thunk_FUN_00487f40();
        iVar4 = thunk_FUN_00487f20();
      }
    }
    piVar5 = piVar5 + 1;
    iVar6 = iVar6 + 1;
  } while ((int)piVar5 < 0x6a438c);
  return;
}




// 0x0054a6d0 FUN_0054a6d0

void FUN_0054a6d0(int *param_1,int param_2)

{
  char cVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  uStack_c = *unaff_FS_OFFSET;
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_00634cba;
  *unaff_FS_OFFSET = &uStack_c;
  iVar5 = *param_1;
  cVar1 = (**(code **)(iVar5 + 0x40))();
  iVar6 = cVar1 + -0x61;
  if ((param_2 == -1) || (param_2 == iVar6)) {
    if ((&g_pTerrainTypeDescriptorTable)[iVar6] != 0) {
      piVar3 = (int *)thunk_FUN_00487ef0();
      iVar4 = thunk_FUN_00487f20();
      while (iVar4 != 0) {
        (**(code **)(*piVar3 + 0x30))();
        piVar3 = (int *)thunk_FUN_00487f40();
        iVar4 = thunk_FUN_00487f20();
      }
      (**(code **)(**(int **)((&g_pTerrainTypeDescriptorTable)[iVar6] + 0x44) + 0x54))();
    }
    sVar2 = (**(code **)(iVar5 + 0x4c))();
    for (iVar5 = (int)sVar2; iVar5 != 0; iVar5 = iVar5 + -1) {
      iVar4 = AllocateWithFallbackHandler(0x44);
      piVar3 = (int *)0x0;
      uStack_4 = 0;
      if (iVar4 != 0) {
        piVar3 = (int *)InitializeMilitaryUnitOrderObject();
      }
      uStack_4 = 0xffffffff;
      InitializeMilitaryRecruitOrderState(0,0xffffffff,iVar6,0);
      iVar4 = *piVar3;
      (**(code **)(iVar4 + 0x18))(param_1);
      (**(code **)(iVar4 + 0xc))();
    }
  }
  *unaff_FS_OFFSET = uStack_c;
  return;
}




// 0x0054a840 FUN_0054a840

void FUN_0054a840(int *param_1,int param_2)

{
  bool bVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int nOrderOwnerNationId;
  undefined4 *unaff_FS_OFFSET;
  int *local_20;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_00634cda;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  nOrderOwnerNationId = 0;
  local_20 = &g_apNationStates;
  do {
    if ((param_2 == -1) || (param_2 == nOrderOwnerNationId)) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
    if ((*local_20 != 0) && (bVar1)) {
      piVar3 = (int *)thunk_FUN_00487ef0();
      iVar4 = thunk_FUN_00487f20();
      while (iVar4 != 0) {
        (**(code **)(*piVar3 + 0x30))();
        piVar3 = (int *)thunk_FUN_00487f40();
        iVar4 = thunk_FUN_00487f20();
      }
      (**(code **)(**(int **)(*local_20 + 0x89c) + 0x54))();
    }
    sVar2 = (**(code **)(*param_1 + 0x4c))();
    for (iVar4 = (int)sVar2; iVar4 != 0; iVar4 = iVar4 + -1) {
      iVar5 = AllocateWithFallbackHandler(0x28);
      piVar3 = (int *)0x0;
      uStack_4 = 0;
      if (iVar5 != 0) {
        piVar3 = (int *)InitializeCivUnitOrderObject();
      }
      uStack_4 = 0xffffffff;
      InitializeCivWorkOrderState(piVar3,0,-1,nOrderOwnerNationId);
      iVar5 = *piVar3;
      (**(code **)(iVar5 + 0x18))(param_1);
      (**(code **)(iVar5 + 0xc))();
      if (!bVar1) {
        (**(code **)(iVar5 + 0x30))();
        (**(code **)(iVar5 + 0x1c))();
      }
    }
    local_20 = local_20 + 1;
    nOrderOwnerNationId = nOrderOwnerNationId + 1;
  } while ((int)local_20 < 0x6a438c);
  *unaff_FS_OFFSET = uStack_c;
  return;
}




// 0x0054aa10 FUN_0054aa10

void FUN_0054aa10(undefined4 *param_1,undefined1 param_2,undefined1 param_3)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  char *pcVar5;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  undefined4 local_10c;
  undefined1 local_108;
  char local_104 [256];
  undefined1 local_4;
  undefined1 local_3;
  
  local_10c = 0x74696d65;
  local_108 = thunk_GetActiveNationId();
  local_118 = 0;
  local_11c = 0xc;
  local_114 = 0;
  local_4 = 0xff;
  local_110 = 0x11c;
  thunk_GetActiveNationId();
  uVar2 = 0xffffffff;
  pcVar4 = (char *)*param_1;
  do {
    pcVar5 = pcVar4;
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    pcVar5 = pcVar4 + 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar5;
  } while (cVar1 != '\0');
  uVar2 = ~uVar2;
  pcVar4 = pcVar5 + -uVar2;
  pcVar5 = local_104;
  for (uVar3 = uVar2 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined4 *)pcVar5 = *(undefined4 *)pcVar4;
    pcVar4 = pcVar4 + 4;
    pcVar5 = pcVar5 + 4;
  }
  for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
    *pcVar5 = *pcVar4;
    pcVar4 = pcVar4 + 1;
    pcVar5 = pcVar5 + 1;
  }
  local_11c = 0xc;
  local_4 = param_2;
  local_3 = param_3;
  local_114 = 0;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_11c,1);
  return;
}




// 0x0054d3d0 FUN_0054d3d0

void FUN_0054d3d0(short param_1,int param_2)

{
  int iVar1;
  short sVar2;
  int iVar3;
  undefined2 *puVar4;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined1 local_38;
  undefined2 local_34;
  short local_30;
  undefined2 local_2e [23];
  
  local_3c = 0x74696d65;
  local_38 = thunk_GetActiveNationId();
  local_48 = 0;
  local_40 = 0x4c;
  local_4c = 0x2d;
  local_34 = *(undefined2 *)(g_pGameFlowState + 0xf0);
  if ((param_2 == -2) || (param_2 == -3)) {
    local_44 = 0;
  }
  else if (param_2 == -1) {
    local_44 = 0xffffffff;
  }
  else {
    local_44 = *(undefined4 *)(g_pGameFlowState + 0x48 + param_2 * 4);
  }
  local_30 = param_1;
  iVar3 = 0;
  iVar1 = (&DAT_006a4280)[param_1];
  puVar4 = local_2e;
  do {
    sVar2 = (short)iVar3;
    iVar3 = iVar3 + 1;
    *puVar4 = *(undefined2 *)(iVar1 + 0x14 + sVar2 * 2);
    puVar4 = puVar4 + 1;
  } while (iVar3 < 0x17);
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_4c,param_2 == -3);
  return;
}




// 0x005493c0 FUN_005493c0

void FUN_005493c0(undefined1 param_1,int param_2,int param_3,undefined2 param_4,undefined2 param_5)

{
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined1 local_14;
  undefined1 local_10;
  int local_c;
  int local_8;
  undefined2 local_4;
  undefined2 local_2;
  
  local_18 = 0x74696d65;
  local_14 = thunk_GetActiveNationId();
  local_10 = param_1;
  local_8 = 0;
  local_24 = 0;
  local_28 = 0x11;
  local_c = param_2;
  local_1c = 0x28;
  if (param_2 == 0) {
    local_8 = *(int *)(g_pGlobalMapState + 0xc);
  }
  else if (param_2 == 1) {
    local_8 = *(int *)(g_pGlobalMapState + 0x10);
  }
  local_8 = param_3 - local_8;
  local_4 = param_4;
  local_2 = param_5;
  local_20 = (*(int *)(g_pLocalizationTable + 0x44) == 1) - 1;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_28,0);
  return;
}




// 0x005494b0 FUN_005494b0

void FUN_005494b0(undefined2 param_1,undefined2 param_2)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined1 local_8;
  undefined2 local_4;
  undefined2 local_2;
  
  local_c = 0x74696d65;
  local_8 = thunk_GetActiveNationId();
  local_18 = 0;
  local_4 = param_1;
  local_14 = 0;
  local_10 = 0x1c;
  local_1c = 0x12;
  local_2 = param_2;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_1c,0);
  return;
}




// 0x00549540 FUN_00549540

void FUN_00549540(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined1 local_2c;
  undefined2 local_28;
  undefined4 local_24 [9];
  
  local_30 = 0x74696d65;
  local_2c = thunk_GetActiveNationId();
  local_3c = 0;
  local_40 = 0x13;
  local_34 = 0x40;
  local_38 = *(undefined4 *)(g_pGameFlowState + 0x48 + param_1 * 4);
  local_28 = (undefined2)param_1;
  puVar2 = local_24;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *param_2;
    param_2 = param_2 + 1;
    puVar2 = puVar2 + 1;
  }
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_40,0);
  return;
}




// 0x005495e0 FUN_005495e0

void FUN_005495e0(undefined2 param_1,undefined1 param_2,undefined1 param_3)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined1 local_8;
  undefined2 local_4;
  undefined1 local_2;
  undefined1 local_1;
  
  local_c = 0x74696d65;
  local_8 = thunk_GetActiveNationId();
  local_4 = param_1;
  local_18 = 0;
  local_10 = 0x1c;
  local_1c = 0x20;
  local_2 = param_2;
  local_1 = param_3;
  local_14 = 0;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_1c,1);
  return;
}




// 0x00549680 FUN_00549680

void FUN_00549680(undefined1 param_1,undefined1 param_2,undefined1 param_3)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined1 local_8;
  undefined1 local_4;
  undefined1 local_3;
  undefined1 local_2;
  
  local_c = 0x74696d65;
  local_8 = thunk_GetActiveNationId();
  local_4 = param_1;
  local_18 = 0;
  local_10 = 0x1c;
  local_1c = 0x21;
  local_3 = param_2;
  local_2 = param_3;
  local_14 = 0;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_1c,1);
  return;
}




// 0x00549720 FUN_00549720

void FUN_00549720(undefined1 param_1,undefined2 param_2)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined1 local_8;
  undefined1 local_4;
  undefined2 local_2;
  
  local_c = 0x74696d65;
  local_8 = thunk_GetActiveNationId();
  local_18 = 0;
  local_4 = param_1;
  local_14 = 0;
  local_10 = 0x1c;
  local_1c = 0x22;
  local_2 = param_2;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_1c,1);
  return;
}




// 0x005498d0 FUN_005498d0

void FUN_005498d0(undefined2 param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)

{
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined1 local_18;
  undefined2 local_14;
  undefined2 local_10;
  undefined2 local_e;
  undefined2 local_c;
  undefined2 local_a;
  undefined2 local_8;
  undefined4 local_4;
  
  local_1c = 0x74696d65;
  local_18 = thunk_GetActiveNationId();
  local_2c = 0x1b;
  local_28 = 0;
  local_20 = 0x2c;
  local_14 = *(undefined2 *)(g_pGameFlowState + 0xf0);
  local_24 = 0;
  local_10 = param_1;
  local_e = param_2;
  local_a = param_4;
  local_c = param_3;
  local_8 = param_5;
  local_4 = param_6;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_2c,0);
  return;
}




// 0x005499b0 FUN_005499b0

void FUN_005499b0(char param_1,undefined2 param_2,undefined2 param_3,undefined2 param_4,
                 undefined2 param_5,undefined2 param_6,undefined2 param_7)

{
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined1 local_14;
  undefined2 local_10;
  undefined2 local_c;
  undefined2 local_a;
  undefined2 local_8;
  undefined2 local_6;
  undefined2 local_4;
  undefined2 local_2;
  
  local_18 = 0x74696d65;
  local_14 = thunk_GetActiveNationId();
  local_28 = 0x1c;
  local_24 = 0;
  local_1c = 0x28;
  local_10 = *(undefined2 *)(g_pGameFlowState + 0xf0);
  local_c = param_2;
  local_a = param_3;
  local_6 = param_6;
  local_20 = -(uint)(param_1 != '\0');
  local_8 = param_5;
  local_4 = param_4;
  local_2 = param_7;
  thunk_EnqueueOrSendTurnEventPacketToNation(&local_28,0);
  return;
}



