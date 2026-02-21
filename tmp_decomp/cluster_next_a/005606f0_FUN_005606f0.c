
void __thiscall FUN_005606f0(int param_1,void *param_2,char *param_3)

{
  short sVar1;
  void *pvVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *unaff_FS_OFFSET;
  undefined1 local_18 [4];
  undefined1 local_14 [4];
  undefined1 local_10 [4];
  undefined4 local_c;
  undefined1 *puStack_8;
  int local_4;
  
  local_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635798;
  *unaff_FS_OFFSET = &local_c;
  iVar4 = 0;
  pvVar2 = thunk_GetNavyPrimaryOrderListHead();
  if (pvVar2 != (void *)0x0) {
    sVar1 = (short)param_3;
    do {
      if ((*(int *)((int)pvVar2 + 8) == param_1) && (*(short *)((int)pvVar2 + 0x14) == sVar1)) {
        iVar4 = thunk_FUN_00550670(pvVar2,0);
      }
      pvVar2 = *(void **)((int)pvVar2 + 0x24);
    } while (pvVar2 != (void *)0x0);
  }
  if (iVar4 == 0) {
    thunk_LoadUiStringResourceByGroupAndIndex(param_2,0x2762,0x10);
  }
  else {
    if (*(int *)(iVar4 + 0x20) == 0) {
      InitializeSharedStringRefFromEmpty();
      local_4 = 5;
      InitializeSharedStringRefFromEmpty();
      local_4._0_1_ = 6;
      StringShared__AssignFromPtr(local_18,(int *)(iVar4 + 0x18));
      thunk_LoadUiStringResourceByGroupAndIndex(&param_3,0x2762,0xf);
      scanBracketExpressions(g_pLocalizationTable,param_2,param_3);
      local_4 = CONCAT31(local_4._1_3_,5);
      ReleaseSharedStringRefIfNotEmpty();
    }
    else {
      InitializeSharedStringRefFromEmpty();
      local_4 = 0;
      InitializeSharedStringRefFromEmpty();
      local_4._0_1_ = 1;
      InitializeSharedStringRefFromEmpty();
      local_4._0_1_ = 2;
      thunk_LoadUiStringResourceByGroupAndIndex(&param_3,0x2762,0xe);
      uVar3 = AssignSharedStringConcatCStrAndRef
                        (local_10,s_Adm__0069578c,*(int *)(iVar4 + 0x20) + 0xc);
      local_4._0_1_ = 3;
      StringSharedRef_AssignFromPtr(uVar3);
      local_4._0_1_ = 4;
      thunk_AssignStringSharedRefFromPointer(local_14);
      local_4._0_1_ = 3;
      ReleaseSharedStringRefIfNotEmpty();
      local_4._0_1_ = 2;
      ReleaseSharedStringRefIfNotEmpty();
      StringShared__AssignFromPtr(local_18,(int *)(iVar4 + 0x18));
      scanBracketExpressions(g_pLocalizationTable,param_2,param_3);
      local_4._0_1_ = 1;
      ReleaseSharedStringRefIfNotEmpty();
      local_4 = (uint)local_4._1_3_ << 8;
      ReleaseSharedStringRefIfNotEmpty();
    }
    local_4 = 0xffffffff;
    ReleaseSharedStringRefIfNotEmpty();
  }
  *unaff_FS_OFFSET = local_c;
  return;
}

