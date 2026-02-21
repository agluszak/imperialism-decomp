
void __thiscall FUN_0054cc00(int param_1,int param_2)

{
  int *dst_ref_ptr;
  bool bVar1;
  char cVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *unaff_FS_OFFSET;
  int local_10;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  iVar4 = param_2;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00634e18;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  local_10 = param_1;
  if (param_2 == -1) {
    iVar4 = 0;
    do {
      thunk_FUN_0054cc00(iVar4);
      iVar4 = iVar4 + 1;
    } while (iVar4 < 7);
  }
  else if ((&g_apNationStates)[param_2] == 0) {
    ConstructSharedStringFromCStrOrResourceId(&DAT_006a13a0);
    local_4 = 0;
    StringShared__AssignFromPtr((void *)(param_1 + 0x78 + iVar4 * 4),&param_2);
    local_4 = 0xffffffff;
    ReleaseSharedStringRefIfNotEmpty();
    *(undefined4 *)(param_1 + 0xbc + iVar4 * 4) = 0x64656164;
  }
  else {
    if ((*(char *)((&g_apNationStates)[param_2] + 0xa0) == '\0') ||
       (cVar2 = thunk_IsNationSlotEligibleForEventProcessing(param_2), cVar2 == '\0')) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
    InitializeSharedStringRefFromEmpty();
    local_4 = 1;
    FormatOverlayTerrainLabelText(&param_2);
    puVar3 = (undefined4 *)&DAT_0069806c;
    if (!bVar1) {
      puVar3 = &DAT_006a13a0;
    }
    ConstructSharedStringFromCStrOrResourceId(puVar3);
    dst_ref_ptr = (int *)(param_1 + 0x78 + iVar4 * 4);
    local_4._0_1_ = 2;
    StringShared__AssignFromPtr(dst_ref_ptr,&local_10);
    local_4 = CONCAT31(local_4._1_3_,1);
    ReleaseSharedStringRefIfNotEmpty();
    AssignStringSharedFromRef(&param_2);
    puVar3 = (undefined4 *)&DAT_006973c8;
    if (!bVar1) {
      puVar3 = &DAT_006a13a0;
    }
    AssignStringSharedFromCStr(puVar3);
    StringShared__AssignFromPtr((void *)(param_1 + 0x94 + iVar4 * 4),dst_ref_ptr);
    cVar2 = thunk_IsNationSlotEligibleForEventProcessing(iVar4);
    if (cVar2 == '\0') {
      *(undefined4 *)(param_1 + 0xbc + iVar4 * 4) = 0x64656361;
    }
    local_4 = 0xffffffff;
    ReleaseSharedStringRefIfNotEmpty();
  }
  *unaff_FS_OFFSET = local_c;
  return;
}

