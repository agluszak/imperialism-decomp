
void __thiscall FUN_0055f780(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  char *unaff_ESI;
  undefined4 *unaff_FS_OFFSET;
  undefined1 local_20 [4];
  int local_1c [3];
  undefined4 local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635740;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  if (param_3 == 0) {
    iVar1 = -1;
    if ((param_2 != 0) && (*(int *)(param_1 + 0x40) != 0)) {
      DAT_006a5aec = DAT_006a5aec * 0x15a4e35 + 1;
      uVar2 = (DAT_006a5aec >> 0xc & 0x7fff) % *(uint *)(param_1 + 0x40);
      if (*(uint *)(param_1 + 0x3c) <= uVar2) {
        thunk_ResizePointerArrayCapacityByRequestedCount(uVar2 + 1);
      }
      if (*(uint *)(param_1 + 0x40) <= uVar2) {
        *(uint *)(param_1 + 0x40) = uVar2 + 1;
      }
      iVar1 = (int)*(short *)(*(int *)(g_pGlobalMapState + 0xc) + 0x14 +
                             *(short *)(*(int *)(*(int *)(param_1 + 0x38) + uVar2 * 4) + 0x42) *
                             0x24);
      if (*(char *)(iVar1 + param_2) == '\0') {
        *(undefined1 *)(iVar1 + param_2) = 1;
      }
      else {
        iVar1 = -1;
      }
    }
    if (iVar1 == -1) {
      if ((char)g_pLocalizationTable[0x1a] == '\0') {
        thunk_GenerateMappedFlavorTextByCurrentContextNation((void *)(param_1 + 8));
      }
      else {
        if (DAT_006984b8 == 0xffffffff) {
          uVar2 = DAT_006a5aec * 0x15a4e35 + 1;
          local_1c[0] = 1;
          DAT_006984b8 = (uVar2 >> 0xc & 0x7fff) % 0x25;
          DAT_006a5aec = uVar2 * 0x15a4e35 + 1;
          local_1c[1] = 7;
          local_1c[2] = 0xb;
          local_10 = 0x17;
          DAT_006984bc = local_1c[DAT_006a5aec >> 0xc & 3];
        }
        InitializeSharedStringRefFromEmpty();
        local_4 = 1;
        (**(code **)(*g_pLocalizationTable + 0x84))
                  (0x275b,CONCAT22((short)((uint)&param_3 >> 0x10),(undefined2)DAT_006984b8),
                   &param_3);
        StringShared__AssignFromPtr((void *)(param_1 + 8),&param_3);
        DAT_006984b8 = DAT_006984b8 + DAT_006984bc;
        if (0x24 < (int)DAT_006984b8) {
          DAT_006984b8 = DAT_006984b8 - 0x25;
        }
        local_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
      }
    }
    else {
      thunk_AssignSharedStringFromIndexedA8EntryNameField(iVar1,param_1 + 8);
    }
  }
  else {
    ConstructSharedStringFromCStrOrResourceId(param_3);
    local_4 = 0;
    StringShared__AssignFromPtr((void *)(param_1 + 8),&param_3);
    local_4 = 0xffffffff;
    ReleaseSharedStringRefIfNotEmpty();
  }
  InitializeSharedStringRefFromEmpty();
  local_4 = 2;
  (**(code **)(*g_pLocalizationTable + 0x84))
            (0x275a,CONCAT22((short)((uint)local_20 >> 0x10),*(undefined2 *)(param_1 + 4)),local_20)
  ;
  InitializeSharedStringRefFromEmpty();
  local_10._0_1_ = 3;
  scanBracketExpressions(g_pLocalizationTable,&puStack_8,unaff_ESI);
  StringShared__AssignFromPtr((void *)(param_1 + 8),(int *)&puStack_8);
  local_10 = CONCAT31(local_10._1_3_,2);
  ReleaseSharedStringRefIfNotEmpty();
  local_10 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = local_1c[1];
  return;
}

