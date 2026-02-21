
void __thiscall FUN_005367d0(int param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = thunk_FUN_005525d0(param_2);
  *(undefined4 *)(param_1 + 0x24) = uVar1;
  *(undefined4 *)(param_2 + 0x2c) = 0;
  if (*(int *)(param_1 + 0x1c) == param_2) {
    *(undefined4 *)(param_1 + 0x1c) = 0;
  }
  return;
}

