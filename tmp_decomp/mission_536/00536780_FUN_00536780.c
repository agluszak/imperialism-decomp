
void __thiscall FUN_00536780(int *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  
  if (*(int **)(param_2 + 0x2c) != (int *)0x0) {
    (**(code **)(**(int **)(param_2 + 0x2c) + 0x8c))(param_2,param_3);
  }
  *(int **)(param_2 + 0x2c) = param_1;
  iVar1 = thunk_FUN_00552650(param_2);
  param_1[9] = iVar1;
  if ((char)param_3 != '\0') {
    (**(code **)(*param_1 + 0x40))();
  }
  return;
}

