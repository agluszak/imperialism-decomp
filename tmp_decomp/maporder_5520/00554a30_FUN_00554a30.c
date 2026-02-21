
int __thiscall FUN_00554a30(int param_1,short param_2)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  for (piVar1 = *(int **)(param_1 + 0x10); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    if ((*(short *)(&DAT_00698120 + *(short *)(*piVar1 + 4) * 0x24) == param_2) &&
       ((char)piVar1[3] != '\0')) {
      iVar2 = iVar2 + 1;
    }
  }
  return iVar2;
}

