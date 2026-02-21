
void __fastcall FUN_005618b0(int param_1)

{
  undefined4 unaff_ESI;
  char *unaff_EDI;
  undefined4 *unaff_FS_OFFSET;
  uint *puStack_20;
  uint local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  uStack_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00635830;
  *unaff_FS_OFFSET = &uStack_c;
  puStack_20 = (uint *)0x561907;
  InitializeSharedStringRefFromEmpty();
  local_4 = 0;
  puStack_20 = (uint *)0x561918;
  InitializeSharedStringRefFromEmpty();
  puStack_20 = &local_10;
  local_4 = CONCAT31(local_4._1_3_,1);
  (**(code **)(*g_pLocalizationTable + 0x84))
            (0x275a,CONCAT22((short)((uint)puStack_20 >> 0x10),*(undefined2 *)(param_1 + 4)));
  scanBracketExpressions(g_pLocalizationTable,&puStack_20,unaff_EDI);
  StringShared__AssignFromPtr((void *)(param_1 + 8),(int *)&puStack_20);
  local_10 = local_10 & 0xffffff00;
  ReleaseSharedStringRefIfNotEmpty();
  local_10 = 0xffffffff;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = unaff_ESI;
  return;
}

