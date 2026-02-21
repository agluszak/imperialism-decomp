
void __fastcall FUN_0055ec60(int *param_1)

{
  if (g_pMapActionContextListHead == param_1) {
    g_pMapActionContextListHead = (int *)param_1[6];
  }
  if (param_1[6] != 0) {
    *(int *)(param_1[6] + 0x1c) = param_1[7];
  }
  if (param_1[7] != 0) {
    *(int *)(param_1[7] + 0x18) = param_1[6];
  }
  param_1[7] = 0;
  param_1[6] = 0;
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + 4))(1);
  }
  return;
}

