
void __fastcall FUN_00556fd0(int param_1)

{
  int iVar1;
  int *piVar2;
  
  for (iVar1 = g_pNavyPrimaryOrderList; iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x24)) {
    *(undefined4 *)(iVar1 + 0xc) = 0;
  }
  piVar2 = *(int **)(param_1 + 4);
  if (piVar2 != (int *)0x0) {
    thunk_FUN_00556820();
    (**(code **)(*piVar2 + 0x1c))();
  }
  *(undefined4 *)(param_1 + 4) = 0;
  thunk_FUN_00564600(0);
  return;
}

