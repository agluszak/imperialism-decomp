
void __thiscall FUN_00554e70(int param_1,void *param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *unaff_FS_OFFSET;
  char *pcVar4;
  undefined1 local_14 [4];
  int local_10;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635280;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  ConstructSharedStringFromCStrOrResourceId(&DAT_006a13a0);
  local_4 = 0;
  StringShared__AssignFromPtr(param_2,&local_10);
  local_4 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  InitializeSharedStringRefFromEmpty();
  local_4 = 1;
  AssignStringSharedFromCStr(&DAT_00698448);
  iVar3 = 0;
  for (iVar1 = *(int *)(param_1 + 0x10); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4)) {
    iVar3 = iVar3 + 1;
  }
  FormatStringWithVarArgsToSharedRef(local_14,&g_szDecimalFormat,iVar3);
  uVar2 = AssignSharedStringConcatRefAndCStr(&param_2,local_14,&DAT_00695794);
  local_4._0_1_ = 2;
  AssignStringSharedFromRef(uVar2);
  local_4._0_1_ = 1;
  ReleaseSharedStringRefIfNotEmpty();
  ConstructSharedStringFromCStrOrResourceId(&DAT_006a13a0);
  local_4._0_1_ = 3;
  StringShared__AssignFromPtr(local_14,(int *)&param_2);
  local_4 = CONCAT31(local_4._1_3_,1);
  ReleaseSharedStringRefIfNotEmpty();
  switch(*(undefined2 *)(param_1 + 8)) {
  case 1:
    AssignStringSharedFromCStr(s_sailing_to_00698428);
    (**(code **)(**(int **)(param_1 + 0xc) + 0x2c))(local_14);
    goto LAB_00554fd0;
  default:
    pcVar4 = s_swabbing_the_decks_006983e8;
    break;
  case 3:
    pcVar4 = s_patrolling_00698438;
    break;
  case 5:
    AssignStringSharedFromCStr(s_invading_0069840c);
    StringShared__AssignFromPtr(local_14,(int *)(*(int *)(param_1 + 0xc) + 0xa4));
    goto LAB_00554fd0;
  case 6:
    pcVar4 = s_blockading_00698418;
    break;
  case 7:
    pcVar4 = s_escorting_00698400;
  }
  AssignStringSharedFromCStr(pcVar4);
LAB_00554fd0:
  AssignStringSharedFromRef(local_14);
  local_4 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = local_c;
  return;
}

