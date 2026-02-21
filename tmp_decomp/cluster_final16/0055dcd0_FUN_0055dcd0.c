
void FUN_0055dcd0(void *param_1,uint param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 *unaff_FS_OFFSET;
  undefined1 local_30 [4];
  int local_2c;
  int local_28;
  char acStack_24 [24];
  undefined4 uStack_c;
  undefined1 *puStack_8;
  int local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635650;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  InitializeSharedStringRefFromEmpty();
  iVar4 = 0;
  local_4 = 0;
  iVar3 = 0;
  local_28 = 0;
  ConstructSharedStringFromCStrOrResourceId(&DAT_006a13a0);
  local_4._0_1_ = 1;
  StringShared__AssignFromPtr(param_1,&local_2c);
  local_4 = (uint)local_4._1_3_ << 8;
  ReleaseSharedStringRefIfNotEmpty();
  iVar2 = 0;
  do {
    if ((param_2 & 1 << ((byte)iVar2 & 0x1f)) == 0) {
      acStack_24[iVar2] = '\0';
    }
    else {
      acStack_24[iVar2] = '\x01';
      iVar3 = iVar3 + 1;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x17);
  do {
    if (acStack_24[iVar4] != '\0') {
      (**(code **)(*g_pLocalizationTable + 0x84))(0x2711,iVar4,local_30);
      iVar2 = local_28;
      if (local_28 == iVar3 + -2) {
        uVar1 = AssignSharedStringConcatRefAndCStr(&param_1,local_30,s_and_00698498);
        local_4._0_1_ = 2;
        AssignStringSharedFromRef(uVar1);
LAB_0055ddf1:
        local_4 = (uint)local_4._1_3_ << 8;
        ReleaseSharedStringRefIfNotEmpty();
      }
      else {
        if (local_28 != iVar3 + -1) {
          uVar1 = AssignSharedStringConcatRefAndCStr(&param_2,local_30,&DAT_00695760);
          local_4._0_1_ = 3;
          AssignStringSharedFromRef(uVar1);
          goto LAB_0055ddf1;
        }
        AssignStringSharedFromRef(local_30);
      }
      local_28 = iVar2 + 1;
    }
    iVar4 = iVar4 + 1;
    if (0x16 < iVar4) {
      local_4 = 0xffffffff;
      ReleaseSharedStringRefIfNotEmpty();
      *unaff_FS_OFFSET = uStack_c;
      return;
    }
  } while( true );
}

