
void __thiscall FUN_00553a50(int param_1,char param_2)

{
  int *piVar1;
  int iVar2;
  
  for (piVar1 = *(int **)(param_1 + 0x10); iVar2 = g_pNavyPrimaryOrderList, piVar1 != (int *)0x0;
      piVar1 = (int *)piVar1[1]) {
    if ((char)piVar1[3] != '\0') {
      *(uint *)(*piVar1 + 0x34) = 2 - (uint)(param_2 != '\0');
    }
  }
  for (; iVar2 != 0; iVar2 = *(int *)(iVar2 + 0x24)) {
    if (((*(int *)(iVar2 + 8) == *(int *)(param_1 + 0x18)) &&
        (*(short *)(iVar2 + 0x14) == *(short *)(param_1 + 0x1c))) && (*(int *)(iVar2 + 0xc) == 0)) {
      thunk_FUN_00553bc0(iVar2);
    }
  }
  for (piVar1 = *(int **)(param_1 + 0x10); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    *(bool *)(piVar1 + 3) = *(int *)(*piVar1 + 0x34) == 0;
  }
  return;
}

