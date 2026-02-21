
int __fastcall FUN_00556010(int param_1)

{
  int iVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = 0;
  for (piVar3 = *(int **)(param_1 + 0x10); piVar3 != (int *)0x0; piVar3 = (int *)piVar3[1]) {
    iVar4 = *piVar3;
    iVar5 = (int)*(short *)(iVar4 + 4);
    sVar2 = *(short *)(iVar4 + 0x30);
    iVar6 = (int)(short)((sVar2 / 100 + (sVar2 >> 0xf)) -
                        (short)((longlong)(int)sVar2 * 0x51eb851f >> 0x3f));
    iVar1 = iVar6 + 5 + (&DAT_00698118)[iVar5 * 9] * 10;
    iVar6 = iVar6 + 5 + (&DAT_00698108)[iVar5 * 9] * 10;
    iVar7 = iVar7 + ((int)(short)(((short)(iVar6 / 10) + (short)(iVar6 >> 0x1f)) -
                                 (short)((longlong)iVar6 * 0x66666667 >> 0x3f)) +
                     ((int)(short)(((short)(iVar1 / 10) + (short)(iVar1 >> 0x1f)) -
                                  (short)((longlong)iVar1 * 0x66666667 >> 0x3f)) +
                     (int)*(short *)(&DAT_0069810c + iVar5 * 9)) * 100 +
                    (int)*(short *)(iVar4 + 0x1c)) / (int)*(short *)(&DAT_00698110 + iVar5 * 0x24);
  }
  return iVar7;
}

