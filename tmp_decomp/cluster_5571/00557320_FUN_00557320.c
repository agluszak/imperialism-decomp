
undefined1 * FUN_00557320(undefined4 param_1,undefined4 param_2,char param_3)

{
  undefined1 *puVar1;
  undefined4 unaff_ESI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uVar2;
  undefined4 uStack_20;
  undefined1 *puStack_1c;
  undefined1 local_14 [4];
  uint local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0063534f;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  local_10 = 0;
  puStack_1c = (undefined1 *)0x55734a;
  InitializeSharedStringRefFromEmpty();
  puStack_1c = local_14;
  local_4 = 1;
  uStack_20 = param_2;
  if (param_3 == '\0') {
    uVar2 = 0x2716;
  }
  else {
    uVar2 = 0x271a;
  }
  (**(code **)(*g_pLocalizationTable + 0x84))(uVar2);
  puVar1 = puStack_8;
  StringSharedRef_AssignFromPtr(&uStack_20);
  puStack_1c = (undefined1 *)0x1;
  local_10 = local_10 & 0xffffff00;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = unaff_ESI;
  return puVar1;
}

