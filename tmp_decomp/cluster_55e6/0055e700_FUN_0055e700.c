
undefined4 * __fastcall FUN_0055e700(undefined4 *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_00635709;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  *param_1 = &g_vtblRefCountedObjectBase;
  local_4 = 0;
  InitializeSharedStringRefFromEmpty();
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[9] = &PTR_LAB_0065c74c;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0xd] = &PTR_LAB_0065c748;
  *param_1 = &PTR_LAB_0065c6d8;
  *(undefined2 *)((int)param_1 + 0x12) = 0xffff;
  *(undefined2 *)(param_1 + 5) = (undefined2)DAT_006a3fc0;
  DAT_006a3fc0 = DAT_006a3fc0 + 1;
  local_4 = CONCAT31(local_4._1_3_,3);
  param_1[3] = 0xffffffff;
  *(undefined2 *)(param_1 + 4) = 0;
  param_1[6] = g_pMapActionContextListHead;
  param_1[7] = 0;
  *(undefined2 *)(param_1 + 0x11) = 0;
  *(undefined2 *)(param_1 + 1) = 0xffff;
  *(undefined2 *)(param_1 + 8) = 0xffff;
  g_pMapActionContextListHead = param_1;
  if (param_1[6] != 0) {
    *(undefined4 **)(param_1[6] + 0x1c) = param_1;
  }
  if (DAT_006a3fc4 != 0) {
    FreeHeapBufferIfNotNull(DAT_006a3fc4);
    DAT_006a3fc4 = 0;
  }
  *unaff_FS_OFFSET = local_c;
  return param_1;
}

