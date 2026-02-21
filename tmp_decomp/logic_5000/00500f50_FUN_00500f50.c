
void __thiscall FUN_00500f50(int param_1,int *param_2)

{
  undefined1 uVar1;
  undefined1 *puVar2;
  int iVar3;
  
  thunk_HandleCityDialogNoOpSlot18(param_2);
  (**(code **)(**(int **)(param_1 + 4) + 0x20))();
  (**(code **)(**(int **)(param_1 + 4) + 0x18))(param_2);
  if (0x2a < DAT_00695278) {
    puVar2 = (undefined1 *)(param_1 + 0x10);
    (**(code **)(*param_2 + 0x3c))(puVar2,10);
    iVar3 = 5;
    do {
      uVar1 = *puVar2;
      *puVar2 = puVar2[1];
      puVar2[1] = uVar1;
      puVar2 = puVar2 + 2;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (0x36 < DAT_00695278) {
    (**(code **)(*param_2 + 0x3c))(param_1 + 0x2e,2);
  }
  return;
}

