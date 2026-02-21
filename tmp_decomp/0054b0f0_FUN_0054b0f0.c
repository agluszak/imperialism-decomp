
void FUN_0054b0f0(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00634d3a;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  puVar1 = (undefined4 *)AllocateWithFallbackHandler(0x1c);
  local_4 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    thunk_ConstructTurnEventPacketBase();
    *puVar1 = &PTR_LAB_0065c0e8;
    puVar2 = puVar1;
  }
  puVar2[6] = param_1;
  local_4 = 0xffffffff;
  thunk_FUN_004878a0(0x706f7365,DAT_006a1344,0,0,0);
  (**(code **)(*DAT_006a1344 + 0x38))(puVar2);
  *unaff_FS_OFFSET = puVar1;
  return;
}

