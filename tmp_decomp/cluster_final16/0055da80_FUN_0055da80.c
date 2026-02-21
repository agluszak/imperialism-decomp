
void FUN_0055da80(void *param_1,uint param_2)

{
  int *piVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *unaff_FS_OFFSET;
  undefined1 local_38 [4];
  int local_34;
  undefined1 local_30 [4];
  undefined1 auStack_2c [4];
  undefined1 local_28 [4];
  char acStack_24 [24];
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635608;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  InitializeSharedStringRefFromEmpty();
  iVar5 = 0;
  local_4 = 0;
  local_34 = 0;
  iVar4 = 0;
  ConstructSharedStringFromCStrOrResourceId(&DAT_006a13a0);
  local_4._0_1_ = 1;
  StringShared__AssignFromPtr(param_1,&local_34);
  local_4._0_1_ = 0;
  ReleaseSharedStringRefIfNotEmpty();
  iVar3 = 0;
  do {
    if ((param_2 & 1 << ((byte)iVar3 & 0x1f)) == 0) {
      acStack_24[iVar3] = '\0';
    }
    else {
      acStack_24[iVar3] = '\x01';
      iVar5 = iVar5 + 1;
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x17);
  iVar3 = 0;
  local_34 = iVar5;
  do {
    if (acStack_24[iVar3] != '\0') {
      if (iVar4 == 0) {
        piVar1 = (int *)thunk_AssignSharedStringFromIndexedSlot7C(&param_2,iVar3);
        local_4._0_1_ = 2;
        StringShared__AssignFromPtr(local_38,piVar1);
      }
      else {
        piVar1 = (int *)thunk_AssignNormalizedCredentialTokenToIndexedSlot(local_30,iVar3);
        local_4._0_1_ = 3;
        StringShared__AssignFromPtr(local_38,piVar1);
      }
      local_4._0_1_ = 0;
      ReleaseSharedStringRefIfNotEmpty();
      if (iVar4 == local_34 + -2) {
        InitializeSharedStringRefFromEmpty();
        local_4._0_1_ = 4;
        (**(code **)(*g_pLocalizationTable + 0x84))(0x275e,4,&param_1);
        uVar2 = AssignSharedStringConcatRefAndRef(auStack_2c,local_38,&param_1);
        local_4._0_1_ = 5;
        AssignStringSharedFromRef(uVar2);
        local_4._0_1_ = 4;
        ReleaseSharedStringRefIfNotEmpty();
LAB_0055dc18:
        local_4._0_1_ = 0;
        ReleaseSharedStringRefIfNotEmpty();
      }
      else {
        if (iVar4 != local_34 + -1) {
          uVar2 = AssignSharedStringConcatRefAndCStr(local_28,local_38,&DAT_00695760);
          local_4._0_1_ = 6;
          AssignStringSharedFromRef(uVar2);
          goto LAB_0055dc18;
        }
        AssignStringSharedFromRef(local_38);
      }
      iVar4 = iVar4 + 1;
    }
    iVar3 = iVar3 + 1;
    if (0x16 < iVar3) {
      local_4 = 0xffffffff;
      ReleaseSharedStringRefIfNotEmpty();
      *unaff_FS_OFFSET = local_c;
      return;
    }
  } while( true );
}

