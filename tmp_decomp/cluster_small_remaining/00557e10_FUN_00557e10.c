
int __thiscall FUN_00557e10(int param_1,short param_2,short param_3)

{
  int *piVar1;
  undefined1 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 4);
  if (iVar4 != 0) {
    do {
      if ((*(short *)(iVar4 + 0x1c) == param_2) && (*(int *)(iVar4 + 8) == 7)) break;
      iVar4 = *(int *)(iVar4 + 0x2c);
    } while (iVar4 != 0);
    if (iVar4 != 0) {
      for (piVar1 = *(int **)(iVar4 + 0x10); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
        if ((*(short *)(*piVar1 + 0x1c) < *(short *)(&DAT_00698114 + *(short *)(*piVar1 + 4) * 0x24)
            ) || (iVar3 = GenerateThreadLocalRandom15(), (int)param_3 <= iVar3 % 100)) {
          uVar2 = 0;
        }
        else {
          uVar2 = 1;
        }
        *(undefined1 *)(piVar1 + 3) = uVar2;
      }
    }
  }
  return iVar4;
}

