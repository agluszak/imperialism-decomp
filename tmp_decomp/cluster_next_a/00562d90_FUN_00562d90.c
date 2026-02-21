
void __thiscall FUN_00562d90(int param_1,short param_2)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int iteration_count;
  int *piVar5;
  undefined4 *puVar6;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_0063589b;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  *(short *)(param_1 + 4) = param_2;
  if (*(int **)(param_1 + 8) != (int *)0x0) {
    (**(code **)(**(int **)(param_1 + 8) + 4))(3);
  }
  iteration_count = (int)param_2;
  piVar1 = (int *)AllocateWithFallbackHandler(iteration_count * 0x48 + 4);
  uStack_4 = 0;
  if (piVar1 == (int *)0x0) {
    piVar5 = (int *)0x0;
  }
  else {
    piVar5 = piVar1 + 1;
    *piVar1 = iteration_count;
    CallCallbackRepeatedly
              (piVar5,0x48,iteration_count,thunk_ConstructTZoneAndLinkIntoGlobalMapActionContextList
              );
  }
  uStack_4 = 0xffffffff;
  *(int **)(param_1 + 8) = piVar5;
  if (piVar5 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  puVar2 = (undefined4 *)AllocateWithFallbackHandler(0x32a0);
  puVar6 = puVar2;
  for (iVar4 = 0xca8; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  iVar4 = thunk_FUN_00562af0(puVar2);
  while (iVar4 != 0) {
    iVar4 = thunk_FUN_00562af0(puVar2);
  }
  iVar4 = 0;
  if (0 < iteration_count) {
    do {
      uVar3 = thunk_FUN_00562c00(puVar2,iVar4 + 0x17);
      thunk_FUN_0055fb60(iVar4 + 0x17,uVar3);
      iVar4 = iVar4 + 1;
    } while (iVar4 < iteration_count);
  }
  FreeHeapBufferIfNotNull(puVar2);
  *unaff_FS_OFFSET = uStack_c;
  return;
}

