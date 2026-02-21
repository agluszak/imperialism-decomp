
uint __fastcall FUN_0054db40(int *param_1)

{
  int iVar1;
  code *pcVar2;
  char cVar3;
  int *piVar4;
  int *dst_ref_ptr;
  int iVar5;
  uint uVar6;
  undefined2 extraout_var;
  int iVar7;
  undefined4 *unaff_FS_OFFSET;
  int iVar8;
  char cStack_2e;
  int iStack_28;
  int local_24;
  undefined4 uStack_20;
  code *local_1c;
  code *local_18;
  int local_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  uint uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_00634eb0;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  local_14 = *param_1;
  local_18 = *(code **)(local_14 + 0x94);
  local_1c = (code *)0x0;
  local_24 = 0x48;
  do {
    pcVar2 = local_1c;
    iVar7 = 0;
    if (*(int *)(g_pGameFlowState + local_24) == 0) {
      iVar7 = 2;
    }
    else if (*(int *)(g_pGameFlowState + local_24) == -2) {
      iVar7 = 3;
    }
    else {
      uVar6 = thunk_FUN_0054b8c0(local_1c);
      if (uVar6 < 0x6275737a) {
        if (uVar6 == 0x62757379) {
          iVar7 = 0;
        }
        else if (uVar6 == 0x61776f6c) {
          iVar7 = 3;
        }
      }
      else if (uVar6 < 0x64656362) {
        if (uVar6 == 0x64656361) {
          iVar7 = 4;
        }
        else if (uVar6 == 0x64656164) {
          iVar7 = 4;
        }
      }
      else if (uVar6 == 0x72656479) {
        iVar7 = 1;
      }
      else if (uVar6 == 0x756e6173) {
        iVar7 = 2;
      }
    }
    piVar4 = (int *)(*local_18)(pcVar2 + 0x72616430);
    iVar8 = *piVar4;
    (**(code **)(iVar8 + 0xc))();
    if ((int)(short)piVar4[0x21] != *(int *)(&UNK_0065c168 + iVar7 * 4)) {
      (**(code **)(iVar8 + 0x1c8))
                (CONCAT22(extraout_var,*(undefined2 *)(&UNK_0065c168 + iVar7 * 4)),1);
    }
    thunk_FUN_00549240();
    piVar4 = (int *)(*local_1c)(pcVar2 + 0x6e616d30);
    iVar8 = *piVar4;
    (**(code **)(iVar8 + 0xc))();
    InitializeSharedStringRefFromEmpty();
    uStack_c = 0;
    InitializeSharedStringRefFromEmpty();
    uStack_c = CONCAT31(uStack_c._1_3_,1);
    (**(code **)(iVar8 + 0x1d0))(&iStack_28);
    iVar1 = local_24;
    dst_ref_ptr = (int *)thunk_FUN_00508c50(&uStack_10,g_pGameFlowState + 0x30 + local_24);
    uStack_4._0_1_ = 2;
    StringShared__AssignFromPtr(&iStack_28,dst_ref_ptr);
    uStack_4 = CONCAT31(uStack_4._1_3_,1);
    ReleaseSharedStringRefIfNotEmpty();
    iVar5 = CompareAnsiStringsWithMbcsAwareness(uStack_20,iStack_28);
    if (iVar5 != 0) {
      (**(code **)(iVar8 + 0x1c8))(&iStack_28,1);
      if (iVar7 == 4) {
        iVar8 = 0x2b6a;
        iVar7 = 0x2b67;
      }
      else if (cStack_2e == '\0') {
        iVar8 = 0x2b6c;
        iVar7 = 0x2b6b;
      }
      else {
        iVar8 = 0x2b6b;
        iVar7 = 0x2b6c;
      }
      thunk_ApplyUiTextStyleAndThemeFlags(piVar4,0,0xe,iVar7,iVar8);
    }
    uStack_4 = uStack_4 & 0xffffff00;
    ReleaseSharedStringRefIfNotEmpty();
    uStack_4 = 0xffffffff;
    ReleaseSharedStringRefIfNotEmpty();
    local_24 = iVar1 + 4;
    local_1c = local_1c + 1;
  } while (local_24 < 100);
  cVar3 = thunk_FUN_0054a9d0();
  if (cVar3 == '\0') {
    if (*(int *)(g_pLocalizationTable + 0x44) == 1) {
      cVar3 = '\x10';
    }
    else {
      cVar3 = (-(g_pGlobalMapState != 0) & 0x14U) + 0x18;
    }
  }
  else {
    iVar7 = thunk_FUN_0054b8c0(0xffffffff);
    if ((iVar7 == 0x62757379) && (*(char *)(g_pGameFlowState + 0xf4) != '\0')) {
      cVar3 = '$';
      if ((short)param_1[0x21] != 0x11f8) {
        (**(code **)(local_14 + 0x1c8))(0x11f8,1);
      }
    }
    else {
      cVar3 = '\x10';
      if ((short)param_1[0x21] != 0x11f9) {
        (**(code **)(local_14 + 0x1c8))(0x11f9,1);
      }
    }
  }
  InitializeSharedStringRefFromEmpty();
  uStack_4 = 3;
  thunk_LoadUiStringResourceByGroupAndIndex(&local_1c,0x2742,cVar3);
  piVar4 = (int *)(*local_18)(0x6d657373);
  iVar7 = *piVar4;
  (**(code **)(iVar7 + 0xc))();
  (**(code **)(iVar7 + 0x1c8))(&uStack_20,1);
  uStack_10 = 0xffffffff;
  uVar6 = ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = local_18;
  return uVar6 & 0xffffff00;
}

