
void __thiscall FUN_004f8ff0(int *param_1,undefined1 *param_2)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  int unaff_EDI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_84;
  int iStack_78;
  undefined4 *puStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 *puStack_68;
  undefined1 *puStack_64;
  undefined4 uStack_60;
  undefined1 **ppuStack_5c;
  undefined4 uStack_58;
  undefined4 uStack_54;
  undefined *puStack_50;
  undefined1 *puVar4;
  undefined1 *puStack_38;
  undefined1 local_24 [4];
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  code *pcStack_18;
  undefined1 local_12;
  undefined1 local_11;
  undefined1 local_10;
  undefined1 local_f;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00632e90;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  puStack_38 = (undefined1 *)0x4f9017;
  InitializeSharedStringRefFromEmpty();
  puStack_38 = &local_20;
  local_4 = 0;
  local_12 = 0;
  local_11 = 0;
  local_10 = 0;
  local_f = 0;
  local_20 = 0;
  local_1f = 0;
  local_1e = 0;
  local_1d = 0;
  MapUiThemeCodeToStyleFlags();
  puStack_38 = param_2;
  thunk_FUN_0048ab70();
  puStack_38 = (undefined1 *)0x61636365;
  pcVar1 = *(code **)(*param_1 + 0x94);
  param_1[0x18] = param_1[8];
  iVar2 = (*pcVar1)();
  param_1[0x1a] = iVar2;
  if (iVar2 == 0) {
                    /* WARNING: Subroutine does not return */
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  iVar2 = (*pcVar1)();
  param_1[0x1b] = iVar2;
  if (iVar2 == 0) {
                    /* WARNING: Subroutine does not return */
    puStack_50 = &UNK_004f90c3;
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  *(undefined2 *)(param_1[0x1a] + 0x92) = 5000;
  *(undefined2 *)(param_1[0x1b] + 0x92) = 5000;
  puStack_50 = (undefined *)0x4f9100;
  BuildUiTextStyleDescriptor();
  piVar3 = (int *)(*pcVar1)();
  iVar2 = *piVar3;
  (**(code **)(iVar2 + 0xc))();
  puVar4 = local_24;
  (**(code **)(iVar2 + 0x1e4))();
  puStack_50 = (undefined *)0x1;
  piVar3[0x27] = unaff_EDI;
  *(undefined1 *)(piVar3 + 0x28) = 1;
  uStack_54 = 0x4f913f;
  (**(code **)(iVar2 + 0x1c4))();
  uStack_54 = 0x74657874;
  uStack_58 = 0x4f914a;
  piVar3 = (int *)(*pcStack_18)();
  iVar2 = *piVar3;
  uStack_58 = 0x4f9153;
  (**(code **)(iVar2 + 0xc))();
  ppuStack_5c = &puStack_38;
  uStack_58 = 0;
  uStack_60 = 0x4f9161;
  (**(code **)(iVar2 + 0x1e4))();
  uStack_60 = 0;
  piVar3[0x27] = (int)puVar4;
  puStack_64 = (undefined1 *)0x1;
  *(undefined1 *)(piVar3 + 0x28) = 1;
  puStack_68 = (undefined4 *)0x4f917d;
  (**(code **)(iVar2 + 0x1c4))();
  puStack_68 = &uStack_54;
  uStack_6c = 6;
  uStack_70 = 0x274a;
  puStack_74 = (undefined4 *)0x4f9197;
  (**(code **)(*g_pLocalizationTable + 0x84))();
  iStack_78 = param_1[0x1a];
  puStack_38 = (undefined1 *)&iStack_78;
  puStack_74 = (undefined4 *)iStack_78;
  thunk_AssignStringSharedRefAndReturnThis();
  InitializeAndRunMainRoutine();
  puStack_74 = &uStack_60;
  iStack_78 = 7;
  (**(code **)(*g_pLocalizationTable + 0x84))();
  thunk_AssignStringSharedRefAndReturnThis(&uStack_6c);
  InitializeAndRunMainRoutine();
  uStack_84 = 0x4f91f9;
  ConstructSharedStringFromCStrOrResourceId();
  uStack_84 = 0x4f920c;
  StringShared__AssignFromPtr(&uStack_6c,(int *)&stack0xffffffbc);
  ReleaseSharedStringRefIfNotEmpty();
  puStack_64 = (undefined1 *)&uStack_84;
  thunk_AssignStringSharedRefAndReturnThis(&uStack_6c);
  InitializeAndRunMainRoutine();
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = uStack_54;
  return;
}

