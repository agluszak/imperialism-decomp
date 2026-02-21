
void __fastcall FUN_00556850(int param_1)

{
  int *piVar1;
  
  while (g_pNavyPrimaryOrderList != (int *)0x0) {
    (**(code **)(*g_pNavyPrimaryOrderList + 0x1c))();
  }
  g_pNavyPrimaryOrderList = (int *)0x0;
  while (g_pNavySecondaryOrderList != (int *)0x0) {
    (**(code **)(*g_pNavySecondaryOrderList + 0x1c))();
  }
  piVar1 = *(int **)(param_1 + 4);
  if (piVar1 != (int *)0x0) {
    thunk_FUN_00556820();
    (**(code **)(*piVar1 + 0x1c))();
  }
  return;
}

