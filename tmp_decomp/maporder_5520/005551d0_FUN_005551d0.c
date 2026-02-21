
void __thiscall FUN_005551d0(int param_1,void *param_2)

{
  undefined4 uVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined1 local_20 [4];
  undefined1 local_1c [4];
  char *local_18;
  undefined1 local_14 [4];
  undefined1 local_10 [4];
  undefined4 local_c;
  undefined1 *puStack_8;
  int local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_006352d0;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  InitializeSharedStringRefFromEmpty();
  local_4 = 0;
  if ((param_1 == 0) || (*(int *)(param_1 + 0x14) == 0)) {
    thunk_LoadUiStringResourceByGroupAndIndex(param_2,0x2762,0xd);
  }
  else if (*(int *)(*(int *)(param_1 + 0x14) + 0x20) == 0) {
    InitializeSharedStringRefFromEmpty();
    local_4._0_1_ = 5;
    thunk_LoadUiStringResourceByGroupAndIndex(&local_18,0x2762,0xf);
    StringShared__AssignFromPtr(local_20,(int *)(*(int *)(param_1 + 0x14) + 0x18));
    scanBracketExpressions(g_pLocalizationTable,param_2,local_18);
    local_4 = (uint)local_4._1_3_ << 8;
    ReleaseSharedStringRefIfNotEmpty();
  }
  else {
    InitializeSharedStringRefFromEmpty();
    local_4._0_1_ = 1;
    InitializeSharedStringRefFromEmpty();
    local_4._0_1_ = 2;
    thunk_LoadUiStringResourceByGroupAndIndex(&local_18,0x2762,0xe);
    uVar1 = AssignSharedStringConcatCStrAndRef
                      (local_10,s_Adm__0069578c,*(int *)(*(int *)(param_1 + 0x14) + 0x20) + 0xc);
    local_4._0_1_ = 3;
    StringSharedRef_AssignFromPtr(uVar1);
    local_4._0_1_ = 4;
    thunk_AssignStringSharedRefFromPointer(local_14);
    local_4._0_1_ = 3;
    ReleaseSharedStringRefIfNotEmpty();
    local_4._0_1_ = 2;
    ReleaseSharedStringRefIfNotEmpty();
    StringShared__AssignFromPtr(local_1c,(int *)(*(int *)(param_1 + 0x14) + 0x18));
    scanBracketExpressions(g_pLocalizationTable,param_2,local_18);
    local_4._0_1_ = 1;
    ReleaseSharedStringRefIfNotEmpty();
    local_4 = (uint)local_4._1_3_ << 8;
    ReleaseSharedStringRefIfNotEmpty();
  }
  local_4 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = local_c;
  return;
}

