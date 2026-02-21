
void __thiscall FUN_005539c0(int param_1,char param_2)

{
  int iVar1;
  int *piVar2;
  undefined1 uVar3;
  
  for (iVar1 = g_pNavyPrimaryOrderList; iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x24)) {
    if (((*(int *)(iVar1 + 8) == *(int *)(param_1 + 0x18)) &&
        (*(short *)(iVar1 + 0x14) == *(short *)(param_1 + 0x1c))) && (*(int *)(iVar1 + 0xc) == 0)) {
      thunk_FUN_00553bc0(iVar1);
    }
  }
  for (piVar2 = *(int **)(param_1 + 0x10); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[1]) {
    if ((param_2 == '\0') && (*(int *)(*piVar2 + 0x34) != 0)) {
      uVar3 = 0;
    }
    else {
      uVar3 = 1;
    }
    *(undefined1 *)(piVar2 + 3) = uVar3;
  }
  return;
}

