
void __fastcall FUN_00561a70(int *param_1)

{
  if (g_pGlobalMapState != 0) {
    if ((short)param_1[8] != -1) {
      thunk_FUN_00515e00((short)param_1[8],0xffffffff);
    }
    if (param_1[3] != -1) {
      thunk_FUN_00515e00((short)param_1[3],0xffffffff);
    }
  }
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

