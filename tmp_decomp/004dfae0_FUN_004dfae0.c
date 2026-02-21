
void __thiscall FUN_004dfae0(int param_1,int *param_2)

{
  undefined2 extraout_var;
  int iVar1;
  undefined4 unaff_EBX;
  int iVar2;
  undefined4 *unaff_FS_OFFSET;
  int iStack_30;
  undefined1 local_18 [4];
  int local_14;
  undefined1 *local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  int local_4;
  
  iVar1 = g_pLocalizationTable;
  uStack_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0063232a;
  *unaff_FS_OFFSET = &uStack_c;
  iVar2 = -1;
  if (*(short *)(iVar1 + 0x114) == 0) {
    iVar2 = (**(code **)(**(int **)(param_1 + 0x98) + 0xc0))();
  }
  else {
    iVar1 = 0;
    do {
      if (((short)*(char *)(g_pGlobalMapState[3] + 4 + (short)iVar1 * 0x24) ==
           *(short *)(param_1 + 0xc)) &&
         ((*(byte *)(g_pGlobalMapState[3] + (short)iVar1 * 0x24 + 0x1c) & 1) != 0)) {
        iVar2 = iVar1;
      }
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x1950);
    if ((short)iVar2 == -1) {
      InitializeSharedStringRefFromEmpty();
      local_4 = 0;
      iStack_30 = 0x4dfb6f;
      ConstructSharedStringFromCStrOrResourceId();
      local_4._0_1_ = 1;
      iStack_30 = 0x4dfb82;
      StringShared__AssignFromPtr(local_18,&local_14);
      local_4 = (uint)local_4._1_3_ << 8;
      ReleaseSharedStringRefIfNotEmpty();
      iStack_30 = 0x4dfb9f;
      AppendSingleByteToSharedStringFromArg();
      iStack_30 = 0x4dfbad;
      AssignStringSharedFromCStr();
      local_10 = (undefined1 *)&iStack_30;
      thunk_AssignStringSharedRefAndReturnThis(local_18);
      thunk_FUN_005d5a70();
      local_4 = 0xffffffff;
      ReleaseSharedStringRefIfNotEmpty();
    }
  }
  *(int *)(param_1 + 0x88) = (int)(short)iVar2;
  iStack_30 = 0x4dfc01;
  local_10 = (undefined1 *)AllocateWithFallbackHandler();
  local_4 = 2;
  if (local_10 == (undefined1 *)0x0) {
    iVar1 = 0;
  }
  else {
    iVar1 = thunk_FUN_005b6c60();
  }
  local_4 = 0xffffffff;
  iStack_30 = 1;
  thunk_FUN_005b6cd0(s_FrogCity_00696760,iVar2);
  iStack_30 = 0x4dfc4a;
  (**(code **)(*param_2 + 0x44))();
  *(undefined1 *)(iVar1 + 0x4f) = 1;
  iStack_30 = iVar1;
  (**(code **)(**(int **)(param_1 + 0x898) + 0x30))();
  (**(code **)(*g_pGlobalMapState + 0x134))
            (CONCAT22(extraout_var,*(undefined2 *)(iVar1 + 0x14)),
             CONCAT22(extraout_var,*(undefined2 *)(param_1 + 0xc)));
  if ((*(char *)(param_1 + 0xa0) == '\0') && (*(int **)(param_1 + 0x98) != (int *)0x0)) {
    (**(code **)(**(int **)(param_1 + 0x98) + 0x44))(param_2);
  }
  *unaff_FS_OFFSET = unaff_EBX;
  return;
}

