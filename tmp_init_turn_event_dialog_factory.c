
int * __fastcall InitializeTurnEventDialogFactoryRegistry(int *pFactoryBootstrap)

{
  int iVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  int iStack_4;
  
  iStack_4 = 0xffffffff;
  puStack_8 = &LAB_0062df8c;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  FUN_0061096b();
  iStack_4 = 0;
  *pFactoryBootstrap = (int)&PTR_LAB_00645eb8;
  iVar1 = AllocateWithFallbackHandler(4);
  iStack_4._0_1_ = 1;
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = thunk_FUN_0049e5f0();
  }
  iStack_4._0_1_ = 0;
  pFactoryBootstrap[0x14] = iVar1;
  iVar1 = AllocateWithFallbackHandler(0x20);
  iStack_4._0_1_ = 2;
  if (iVar1 == 0) {
    DAT_006a1b24 = (void *)0x0;
  }
  else {
    DAT_006a1b24 = (void *)thunk_FUN_00491ad0();
  }
  iStack_4 = (uint)iStack_4._1_3_ << 8;
  RegisterDialogFactoryCallback(DAT_006a1b24,0x401401);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x403977);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x4070ae);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x403f99);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x4059cf);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x407d65);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x407013);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x4053f8);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x4033be);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x405a10);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x406690);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x4056fa);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x405402);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x401235);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x409773);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x407531);
  RegisterDialogFactoryCallback(DAT_006a1b24,0x406410);
  *unaff_FS_OFFSET = uStack_c;
  return pFactoryBootstrap;
}

