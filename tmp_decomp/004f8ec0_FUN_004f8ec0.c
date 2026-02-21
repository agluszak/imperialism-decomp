
undefined4 * FUN_004f8ec0(void)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00632e6a;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  puVar1 = (undefined4 *)AllocateWithFallbackHandler(0x70);
  local_4 = 0;
  if (puVar1 != (undefined4 *)0x0) {
    thunk_ConstructUiResourceEntryBase();
    puVar1[0x18] = 0;
    *puVar1 = &PTR_LAB_00655fb0;
    puVar1[0x1a] = 0;
    puVar1[0x1b] = 0;
    *unaff_FS_OFFSET = local_c;
    return puVar1;
  }
  *unaff_FS_OFFSET = local_c;
  return (undefined4 *)0x0;
}

