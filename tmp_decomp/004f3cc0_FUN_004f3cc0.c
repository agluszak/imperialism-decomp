
void __fastcall FUN_004f3cc0(int param_1)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  uint local_4;
  
  puStack_8 = &LAB_00632b40;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  local_4 = 1;
  FUN_005e7e10(param_1 + 0x2078,0x30,0x17,&LAB_004038a0);
  local_4 = local_4 & 0xffffff00;
  FUN_005e7e10(param_1 + 0x1eac,0x14,0x17,&LAB_004077bb);
  local_4 = 0xffffffff;
  thunk_DestructCityDialogSharedBaseState();
  *unaff_FS_OFFSET = local_c;
  return;
}

