
void __fastcall FUN_005548e0(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  iVar3 = 0;
  for (piVar1 = *(int **)(param_1 + 0x10); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    iVar2 = iVar2 + *(int *)(*piVar1 + 0x10);
    iVar3 = iVar3 + 1;
  }
  if (iVar3 == 0) {
    *(undefined4 *)(param_1 + 4) = 0;
    return;
  }
  *(int *)(param_1 + 4) = (iVar3 / 2 + iVar2) / iVar3;
  return;
}

