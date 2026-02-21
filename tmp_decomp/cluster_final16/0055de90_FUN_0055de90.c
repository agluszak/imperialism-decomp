
void FUN_0055de90(void *param_1,undefined4 param_2)

{
  undefined4 *unaff_FS_OFFSET;
  int local_10;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635678;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  InitializeSharedStringRefFromEmpty();
  local_4 = 0;
  thunk_AssignSharedStringFromIndexedA8EntryNameField(param_2,&local_10);
  StringShared__AssignFromPtr(param_1,&local_10);
  local_4 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = local_c;
  return;
}

