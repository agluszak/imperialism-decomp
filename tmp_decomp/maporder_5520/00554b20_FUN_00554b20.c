
void __thiscall FUN_00554b20(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined2 extraout_var;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 *unaff_FS_OFFSET;
  int local_48;
  int local_44 [14];
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635210;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  ConstructSharedStringFromCStrOrResourceId(&DAT_006a13a0);
  puVar1 = param_2;
  local_4 = 0;
  StringShared__AssignFromPtr(param_2,&local_48);
  local_4 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  piVar4 = local_44;
  for (iVar3 = 0xe; iVar3 != 0; iVar3 = iVar3 + -1) {
    *piVar4 = 0;
    piVar4 = piVar4 + 1;
  }
  for (piVar4 = *(int **)(param_1 + 0x10); piVar4 != (int *)0x0; piVar4 = (int *)piVar4[1]) {
    local_44[*(short *)(*piVar4 + 4)] = local_44[*(short *)(*piVar4 + 4)] + 1;
  }
  iVar3 = 0;
  piVar4 = local_44;
  do {
    if (0 < *piVar4) {
      InitializeSharedStringRefFromEmpty();
      local_4 = 1;
      thunk_FUN_00550c20(&param_2,iVar3,CONCAT22(extraout_var,(short)*piVar4));
      iVar2 = CompareAnsiStringsWithMbcsAwareness(*puVar1,&DAT_006a13a0);
      if (iVar2 != 0) {
        AssignStringSharedFromCStr(&DAT_00695760);
      }
      AssignStringSharedFromRef(&param_2);
      local_4 = 0xffffffff;
      ReleaseSharedStringRefIfNotEmpty();
    }
    iVar3 = iVar3 + 1;
    piVar4 = piVar4 + 1;
  } while (iVar3 < 0xe);
  *unaff_FS_OFFSET = local_c;
  return;
}

