
void __fastcall TInvadeMission_VtblSlot1C(int *param_1)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar3;
  
  (**(code **)(*(int *)param_1[0xd] + 0x1c))();
  (**(code **)(*(int *)(&g_apNationStates)[(short)param_1[1]] + 0xc))();
  thunk_FUN_004e8b50((int)(short)param_1[0xc],0);
  iVar2 = thunk_InitializeLinkedListCursorFromOwnerHead();
  bVar1 = thunk_LinkedListCursorHasCurrent();
  iVar3 = CONCAT31(extraout_var,bVar1);
  while (iVar3 != 0) {
    *(undefined4 *)(iVar2 + 0x40) = 0;
    iVar2 = thunk_AdvanceLinkedListCursor();
    bVar1 = thunk_LinkedListCursorHasCurrent();
    iVar3 = CONCAT31(extraout_var_00,bVar1);
  }
  (**(code **)(*(int *)param_1[6] + 0x5c))();
  if ((int *)param_1[6] != (int *)0x0) {
    (**(code **)(*(int *)param_1[6] + 0x58))();
  }
  param_1[6] = 0;
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + 4))(1);
  }
  return;
}

