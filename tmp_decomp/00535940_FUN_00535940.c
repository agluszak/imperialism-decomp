
int * FUN_00535940(undefined4 param_1,undefined4 param_2,short param_3,undefined4 param_4)

{
  int iVar1;
  bool bVar2;
  char cVar3;
  int *piVar4;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  
  piVar4 = (int *)thunk_InitializeLinkedListCursorFromOwnerHead();
  bVar2 = thunk_LinkedListCursorHasCurrent();
  if (CONCAT31(extraout_var,bVar2) == 0) {
    return (int *)0x0;
  }
  do {
    iVar1 = *piVar4;
    (**(code **)(iVar1 + 0xc))();
    cVar3 = (**(code **)(iVar1 + 0x4c))(param_2,(int)param_3,param_4);
    if (cVar3 != '\0') {
      return piVar4;
    }
    piVar4 = (int *)thunk_AdvanceLinkedListCursor();
    bVar2 = thunk_LinkedListCursorHasCurrent();
  } while (CONCAT31(extraout_var_00,bVar2) != 0);
  return (int *)0x0;
}

