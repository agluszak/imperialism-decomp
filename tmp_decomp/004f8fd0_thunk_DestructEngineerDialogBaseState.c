
void __fastcall thunk_DestructEngineerDialogBaseState(undefined4 *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  uint uStack_4;
  
  puStack_8 = &LAB_0062ec23;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  *param_1 = &PTR_LAB_00649858;
  uStack_4 = 1;
  if ((int *)param_1[0x11] != (int *)0x0) {
    (**(code **)(*(int *)param_1[0x11] + 4))(1);
  }
  FreeHeapBufferIfNotNull(param_1[0x12]);
  uStack_4 = uStack_4 & 0xffffff00;
  ReleaseSharedStringRefIfNotEmpty();
  *param_1 = &PTR_LAB_0066fec4;
  *unaff_FS_OFFSET = uStack_c;
  return;
}

