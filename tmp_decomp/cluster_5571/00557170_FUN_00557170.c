
int __thiscall FUN_00557170(int param_1,short param_2,int param_3,int param_4)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar3 = 0;
  for (iVar1 = *(int *)(param_1 + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x2c)) {
    if ((((*(short *)(iVar1 + 0x1c) == param_2) && (*(int *)(iVar1 + 8) == 5)) &&
        (*(int *)(iVar1 + 0xc) == param_3)) &&
       ((param_4 == 0 || (*(int *)(iVar1 + 0x18) == param_4)))) {
      iVar5 = 0;
      for (piVar2 = *(int **)(iVar1 + 0x10); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[1]) {
        if (*(short *)(*piVar2 + 0x1c) < 1) {
          iVar4 = 0;
        }
        else {
          iVar4 = (int)*(short *)(&g_industryActionCostWeightResCode10 + *(short *)(*piVar2 + 4) * 2
                                 );
        }
        iVar5 = iVar5 + iVar4;
      }
      iVar3 = iVar3 + iVar5;
    }
  }
  return iVar3;
}

