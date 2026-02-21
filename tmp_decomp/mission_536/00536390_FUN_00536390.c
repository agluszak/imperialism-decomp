
undefined4 * FUN_00536390(void)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0063430a;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  puVar1 = (undefined4 *)AllocateWithFallbackHandler(0x3c);
  local_4 = 0;
  if (puVar1 != (undefined4 *)0x0) {
    thunk_ConstructTMission();
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
    puVar1[8] = 0;
    puVar1[9] = 0;
    puVar1[10] = 0;
    *puVar1 = &g_vtblTNavyMission;
    puVar1[0xb] = 0;
    puVar1[0xc] = 0;
    puVar1[0xd] = 0;
    puVar1[0xe] = 0;
    *unaff_FS_OFFSET = local_c;
    return puVar1;
  }
  *unaff_FS_OFFSET = local_c;
  return (undefined4 *)0x0;
}

