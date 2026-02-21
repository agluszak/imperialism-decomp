
undefined4 * __fastcall FUN_004e3710(undefined4 *param_1)

{
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  puStack_8 = &LAB_00632463;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  *param_1 = &g_vtblRefCountedObjectBase;
  local_4 = 0;
  InitializeSharedStringRefFromEmpty();
  local_4 = CONCAT31(local_4._1_3_,1);
  InitializeSharedStringRefFromEmpty();
  *param_1 = &PTR_LAB_00653c90;
  *unaff_FS_OFFSET = local_c;
  return param_1;
}

