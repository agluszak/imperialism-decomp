
int * __thiscall FUN_005525d0(int *param_1,int param_2)

{
  int *piVar1;
  
  if (param_1 == (int *)0x0) {
    return (int *)0x0;
  }
  if (param_2 == *param_1) {
    piVar1 = (int *)param_1[1];
    if (piVar1 != (int *)0x0) {
      piVar1[2] = param_1[2];
    }
    if (param_1[2] != 0) {
      *(int *)(param_1[2] + 4) = param_1[1];
    }
    FreeHeapBufferIfNotNull(param_1);
    return piVar1;
  }
  thunk_FUN_005525d0(param_2);
  return param_1;
}

