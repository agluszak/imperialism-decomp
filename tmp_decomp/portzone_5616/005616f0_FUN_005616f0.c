
void __fastcall FUN_005616f0(undefined4 *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_c = *unaff_FS_OFFSET;
  puStack_8 = &LAB_00635808;
  *unaff_FS_OFFSET = &local_c;
  *param_1 = &PTR_LAB_0065c6d8;
  local_4 = 0;
  if (g_pMapActionContextListHead == param_1) {
    g_pMapActionContextListHead = (undefined4 *)param_1[6];
  }
  if (param_1[6] != 0) {
    *(undefined4 *)(param_1[6] + 0x1c) = param_1[7];
  }
  if (param_1[7] != 0) {
    *(undefined4 *)(param_1[7] + 0x18) = param_1[6];
  }
  param_1[7] = 0;
  param_1[6] = 0;
  param_1[0xd] = &PTR_LAB_0065c754;
  if (param_1[0xe] != 0) {
    FreeHeapBlockWithAllocatorTracking(param_1[0xe]);
  }
  param_1[9] = &PTR_LAB_0065c750;
  if (param_1[10] != 0) {
    FreeHeapBlockWithAllocatorTracking(param_1[10]);
  }
  ReleaseSharedStringRefIfNotEmpty();
  *param_1 = &PTR_LAB_0066fec4;
  *unaff_FS_OFFSET = local_c;
  return;
}

