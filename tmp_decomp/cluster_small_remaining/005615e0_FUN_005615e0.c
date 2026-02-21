
undefined4 * FUN_005615e0(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_006357ea;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  puVar1 = (undefined4 *)AllocateWithFallbackHandler(0x4c);
  local_4 = 0;
  puVar2 = (undefined4 *)0x0;
  if (puVar1 != (undefined4 *)0x0) {
    thunk_ConstructTZoneAndLinkIntoGlobalMapActionContextList();
    *(undefined2 *)(puVar1 + 0x12) = 0xffff;
    *puVar1 = &PTR_thunk_GetTPortZoneClassName_0065c758;
    puVar2 = puVar1;
  }
  *unaff_FS_OFFSET = local_c;
  return puVar2;
}

