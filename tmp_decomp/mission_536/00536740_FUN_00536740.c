
undefined4 __fastcall FUN_00536740(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x24);
  while (piVar1 != (int *)0x0) {
    *(undefined4 *)(**(int **)(param_1 + 0x24) + 0x2c) = 0;
    piVar1 = thunk_DeleteMapOrderChildLinkAndReturnNext(*(int **)(param_1 + 0x24));
    *(int **)(param_1 + 0x24) = piVar1;
  }
  return 1;
}

