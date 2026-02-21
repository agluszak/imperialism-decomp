
undefined4 * FUN_004caa50(void)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0063179a;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  puVar1 = (undefined4 *)AllocateWithFallbackHandler(0xbc);
  local_4 = 0;
  if (puVar1 != (undefined4 *)0x0) {
    thunk_ConstructUiClickablePictureResourceEntry();
    *puVar1 = &PTR_LAB_00643a40;
    puVar1[0x26] = 0;
    *unaff_FS_OFFSET = local_c;
    return puVar1;
  }
  *unaff_FS_OFFSET = local_c;
  return (undefined4 *)0x0;
}

