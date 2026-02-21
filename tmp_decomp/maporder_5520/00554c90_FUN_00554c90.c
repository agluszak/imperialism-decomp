
void __fastcall FUN_00554c90(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *unaff_FS_OFFSET;
  void *unaff_retaddr;
  undefined1 local_20 [8];
  undefined1 local_18 [4];
  char *local_14;
  undefined4 local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  uStack_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635248;
  *unaff_FS_OFFSET = &uStack_c;
  iVar2 = 0;
  for (iVar1 = *(int *)(param_1 + 0x10); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4)) {
    iVar2 = iVar2 + 1;
  }
  InitializeSharedStringRefFromEmpty();
  local_4 = 0;
  InitializeSharedStringRefFromEmpty();
  local_4._0_1_ = 1;
  InitializeSharedStringRefFromEmpty();
  local_4._0_1_ = 2;
  InitializeSharedStringRefFromEmpty();
  local_4._0_1_ = 3;
  InitializeSharedStringRefFromEmpty();
  local_4 = CONCAT31(local_4._1_3_,4);
  thunk_LoadUiStringResourceByGroupAndIndex(&local_10,0x2762,(iVar2 != 1) + '\x11');
  FormatOverlayTerrainLabelText(&local_14);
  (**(code **)(**(int **)(param_1 + 0x18) + 0x2c))(local_18);
  FormatStringWithVarArgsToSharedRef(local_20,&g_szDecimalFormat,iVar2);
  thunk_LoadUiStringResourceByGroupAndIndex(&stack0xffffffdc,0x2762,*(short *)(param_1 + 8) + 0x13);
  scanBracketExpressions(g_pLocalizationTable,unaff_retaddr,local_14);
  puStack_8._0_1_ = 3;
  ReleaseSharedStringRefIfNotEmpty();
  puStack_8._0_1_ = 2;
  ReleaseSharedStringRefIfNotEmpty();
  puStack_8._0_1_ = 1;
  ReleaseSharedStringRefIfNotEmpty();
  puStack_8 = (undefined1 *)((uint)puStack_8._1_3_ << 8);
  ReleaseSharedStringRefIfNotEmpty();
  puStack_8 = (undefined1 *)0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = local_10;
  return;
}

