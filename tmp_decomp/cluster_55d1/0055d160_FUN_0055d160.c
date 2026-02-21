
undefined4 * FUN_0055d160(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0063551a;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  puVar1 = (undefined4 *)AllocateWithFallbackHandler(0x98);
  local_4 = 0;
  puVar2 = (undefined4 *)0x0;
  if (puVar1 != (undefined4 *)0x0) {
    thunk_ConstructPictureResourceEntryBase();
    *puVar1 = &PTR_thunk_GetTNewspaperViewTypeNamePointer_00641390;
    puVar2 = puVar1;
  }
  *unaff_FS_OFFSET = local_c;
  return puVar2;
}

