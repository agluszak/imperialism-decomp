
void __thiscall FUN_00500fe0(int param_1,int *param_2)

{
  code *pcVar1;
  int unaff_EBX;
  int iVar2;
  
  thunk_HandleCityDialogNoOpSlot14(param_2);
  (**(code **)(**(int **)(param_1 + 4) + 0x14))(param_2);
  iVar2 = 5;
  pcVar1 = *(code **)(*param_2 + 0x78);
  do {
    (*pcVar1)(&stack0x00000000,2);
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  (*pcVar1)(unaff_EBX + 0x2e,2);
  return;
}

