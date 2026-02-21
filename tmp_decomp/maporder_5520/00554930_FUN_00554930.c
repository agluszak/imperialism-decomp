
void __thiscall FUN_00554930(int param_1,short param_2,char param_3)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x10);
  if (piVar1 != (int *)0x0) {
    while ((*(short *)(&DAT_00698120 + *(short *)(*piVar1 + 4) * 0x24) != param_2 ||
           ((char)piVar1[3] == param_3))) {
      piVar1 = (int *)piVar1[1];
      if (piVar1 == (int *)0x0) {
        return;
      }
    }
    *(char *)(piVar1 + 3) = param_3;
    if (param_3 != '\0') {
      *(undefined4 *)(*piVar1 + 0x34) = 0;
    }
  }
  return;
}

