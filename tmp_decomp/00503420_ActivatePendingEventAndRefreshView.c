
/* Activates a selected pending event entry, updates per-entry seen/current-nation fields, and
   refreshes associated UI panels/text for event details. */

void __thiscall ActivatePendingEventAndRefreshView(int param_1,int param_2)

{
  int iVar1;
  undefined2 uVar2;
  short sVar3;
  int iVar4;
  int *piVar5;
  short unaff_DI;
  uint *unaff_FS_OFFSET;
  undefined4 uStack_6c;
  int iStack_68;
  undefined *puStack_64;
  uint uVar6;
  uint uStack_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00633590;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (uint)&uStack_c;
  InitializeSharedStringRefFromEmpty();
  local_4 = 0;
  *(undefined1 *)(param_2 + 10) = 1;
  uVar2 = (**(code **)(*g_pLocalizationTable + 0x3c))();
  *(undefined2 *)(param_2 + 8) = uVar2;
  thunk_InitializeUiTextStyleDescriptor();
  if (*(int *)(param_1 + 8) == 0) {
    iVar4 = (**(code **)(*g_pUiViewManager + 0x28))();
    *(int *)(param_1 + 8) = iVar4;
    if (iVar4 == 0) {
                    /* WARNING: Subroutine does not return */
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    (**(code **)(*g_pUiRuntimeContext + 0x44))();
    (**(code **)(**(int **)(param_1 + 8) + 0xf0))();
    (**(code **)(**(int **)(param_1 + 8) + 0x9c))();
  }
  piVar5 = (int *)(**(code **)(**(int **)(param_1 + 8) + 0x94))();
  piVar5[0x24] = param_2;
  ConstructSharedStringFromCStrOrResourceId();
  puStack_8 = (undefined1 *)CONCAT31(puStack_8._1_3_,1);
  (**(code **)(**(int **)(param_1 + 8) + 0x1d4))();
  uStack_c = uStack_c & 0xffffff00;
  ReleaseSharedStringRefIfNotEmpty();
  local_4 = (**(code **)(*g_pUiRuntimeContext + 0x38))();
  sVar3 = *(short *)(param_2 + 6);
  if (sVar3 == 0x1a0b) {
    local_4 = 0;
  }
  else if (sVar3 == 0x1a0d) {
    local_4 = 2;
  }
  else if (sVar3 == 0x1a0c) {
    local_4 = 1;
  }
  iVar4 = *piVar5;
  (**(code **)(iVar4 + 0x1c8))();
  piVar5 = (int *)(**(code **)(**(int **)(param_1 + 8) + 0x94))();
  iVar1 = *piVar5;
  (**(code **)(iVar1 + 0xc))();
  if (piVar5 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
    puStack_64 = &UNK_005035d7;
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  sVar3 = thunk_GetActiveNationId();
  if (-1 < sVar3) {
    sVar3 = thunk_GetActiveNationId();
    if (sVar3 < 7) {
      uVar6 = 0;
      thunk_GetActiveNationId();
      (**(code **)(iVar1 + 0x1c8))();
      goto LAB_00503638;
    }
  }
  uVar6 = 0;
  (**(code **)(iVar1 + 0xa4))();
LAB_00503638:
  piVar5 = (int *)(**(code **)(iVar4 + 0x94))();
  puStack_64 = (undefined *)0x1;
  iVar4 = *piVar5;
  iStack_68 = 0x503655;
  (**(code **)(iVar4 + 0xa4))();
  iStack_68 = 1;
  uStack_6c = 0;
  (**(code **)(iVar4 + 0xa8))();
  (**(code **)(iVar4 + 0x1c4))(1,0);
  (**(code **)(iVar4 + 0x1b4))(&stack0xffffffb0,0);
  thunk_BuildUiMessageTextFromBracketTemplate
            (g_pLocalizationTable,&uStack_6c,0x2749,6,0x2749,(int)unaff_DI);
  (**(code **)(iVar4 + 0x1c8))(&uStack_6c,0);
  (**(code **)(iStack_68 + 0x1d4))();
  ReleaseSharedStringRefIfNotEmpty();
  *unaff_FS_OFFSET = uVar6;
  return;
}

