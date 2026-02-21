
void __fastcall thunk_DestructCityDialogSharedBaseState(undefined4 *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  puStack_8 = &LAB_0062efcb;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  *param_1 = &PTR_LAB_0064a930;
  uStack_4 = 0;
  if (*(short *)(param_1 + 0x21) != -1) {
    thunk_DecrementDialogResourceRefCountByShortIdAndCleanup
              (CONCAT22((short)((uint)uStack_c >> 0x10),*(short *)(param_1 + 0x21)));
  }
  *(undefined2 *)(param_1 + 0x21) = 0xffff;
  param_1[0x22] = 0;
  param_1[0x23] = 0;
  *param_1 = &PTR_LAB_00649858;
  uStack_4 = 2;
  if ((int *)param_1[0x11] != (int *)0x0) {
    (**(code **)(*(int *)param_1[0x11] + 4))(1);
  }
  FreeHeapBufferIfNotNull(param_1[0x12]);
  uStack_4 = CONCAT31(uStack_4._1_3_,1);
  ReleaseSharedStringRefIfNotEmpty();
  *param_1 = &PTR_LAB_0066fec4;
  *unaff_FS_OFFSET = uStack_c;
  return;
}

