
void __fastcall FUN_004f4620(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int *piVar3;
  code *pcVar4;
  short sVar5;
  undefined1 **unaff_EDI;
  undefined4 *unaff_FS_OFFSET;
  undefined1 *puStack_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined *puStack_3c;
  code *local_18;
  int local_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00632b88;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  InitializeSharedStringRefFromEmpty();
  local_4 = 0;
  piVar3 = param_1 + 0x28;
  pcVar4 = *(code **)(*param_1 + 0x94);
  local_10 = 6;
  do {
    iVar1 = (*pcVar4)();
    *piVar3 = iVar1;
    if (iVar1 == 0) {
                    /* WARNING: Subroutine does not return */
      puStack_3c = &UNK_004f468e;
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    piVar3 = piVar3 + 1;
    local_10 = local_10 + -1;
  } while (local_10 != 0);
  (**(code **)(*(int *)param_1[0x28] + 0x1a4))();
  (**(code **)(*(int *)param_1[0x28] + 0x1a0))();
  sVar5 = 0;
  do {
    (*pcVar4)();
    puStack_3c = (undefined *)0x2733;
    uStack_40 = 0x4f4707;
    (**(code **)(*g_pLocalizationTable + 0x84))();
    puStack_3c = (undefined *)0x4f4719;
    thunk_AssignStringSharedRefAndReturnThis();
    InitializeAndRunMainRoutine();
    sVar5 = sVar5 + 1;
    pcVar4 = local_18;
  } while (sVar5 < 6);
  if ((short)g_pLocalizationTable[2] == 6) {
    uVar2 = (*local_18)();
    puStack_3c = (undefined *)0x274a;
    uStack_40 = 0x4f4766;
    (**(code **)(*g_pLocalizationTable + 0x84))();
    puStack_48 = &stack0xffffffd4;
    uStack_40 = uVar2;
    thunk_AssignStringSharedRefAndReturnThis();
    puStack_48 = (undefined1 *)0x4f477d;
    thunk_EnableAndProcessFlagWithSharedStringCleanup();
    uStack_40 = DAT_00696980;
    uStack_44 = 0x4f478a;
    uStack_44 = (*local_18)();
    unaff_EDI = &puStack_48;
    thunk_FUN_004ac370();
    thunk_EnableAndProcessFlagWithSharedStringCleanup();
    uStack_44 = DAT_00696984;
    puStack_48 = (undefined1 *)0x4f47b0;
    puStack_48 = (undefined1 *)(*local_18)();
    thunk_FUN_004ac370(PTR_DAT_00654ec8);
    thunk_EnableAndProcessFlagWithSharedStringCleanup();
  }
  else {
    piVar3 = (int *)(*local_18)();
    puStack_3c = PTR_DAT_00654ec8;
    uStack_40 = 0x4f47f0;
    thunk_FUN_004ac370();
    puStack_3c = (undefined *)0x4f47f5;
    InitializeAndRunMainRoutine();
    puStack_3c = (undefined *)0x4f4809;
    (**(code **)(*piVar3 + 0xf0))();
  }
  puStack_48 = (undefined1 *)0x4f481a;
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = unaff_EDI;
  return;
}

