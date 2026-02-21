
bool __thiscall FUN_00555de0(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  short sVar4;
  int iVar6;
  int iVar7;
  int local_14;
  int local_c [3];
  int iVar5;
  
  piVar1 = *(int **)(param_1 + 0x10);
  local_c[0] = 200;
  local_c[1] = 100;
  local_c[2] = 0x32;
  local_14 = 0;
  local_14._0_2_ = 0;
  for (; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    iVar7 = *piVar1;
    iVar2 = (int)*(short *)(iVar7 + 4);
    sVar4 = *(short *)(iVar7 + 0x30);
    iVar6 = (int)(short)((sVar4 / 100 + (sVar4 >> 0xf)) -
                        (short)((longlong)(int)sVar4 * 0x51eb851f >> 0x3f));
    iVar5 = iVar6 + 5 + (&DAT_00698118)[iVar2 * 9] * 10;
    iVar6 = iVar6 + 5 + (&DAT_00698108)[iVar2 * 9] * 10;
    local_14 = local_14 +
               ((int)(short)(((short)(iVar6 / 10) + (short)(iVar6 >> 0x1f)) -
                            (short)((longlong)iVar6 * 0x66666667 >> 0x3f)) +
                ((int)(short)(((short)(iVar5 / 10) + (short)(iVar5 >> 0x1f)) -
                             (short)((longlong)iVar5 * 0x66666667 >> 0x3f)) +
                (int)*(short *)(&DAT_0069810c + iVar2 * 9)) * 100 + (int)*(short *)(iVar7 + 0x1c)) /
               (int)*(short *)(&DAT_00698110 + iVar2 * 0x24);
  }
  iVar5 = 0;
  sVar4 = 0;
  for (piVar1 = *(int **)(param_2 + 0x10); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    iVar2 = *piVar1;
    iVar3 = (int)*(short *)(iVar2 + 4);
    sVar4 = *(short *)(iVar2 + 0x30);
    iVar7 = (int)(short)((sVar4 / 100 + (sVar4 >> 0xf)) -
                        (short)((longlong)(int)sVar4 * 0x51eb851f >> 0x3f));
    iVar6 = iVar7 + 5 + (&DAT_00698118)[iVar3 * 9] * 10;
    iVar7 = iVar7 + 5 + (&DAT_00698108)[iVar3 * 9] * 10;
    iVar5 = iVar5 + ((int)(short)(((short)(iVar7 / 10) + (short)(iVar7 >> 0x1f)) -
                                 (short)((longlong)iVar7 * 0x66666667 >> 0x3f)) +
                     ((int)(short)(((short)(iVar6 / 10) + (short)(iVar6 >> 0x1f)) -
                                  (short)((longlong)iVar6 * 0x66666667 >> 0x3f)) +
                     (int)*(short *)(&DAT_0069810c + iVar3 * 9)) * 100 +
                    (int)*(short *)(iVar2 + 0x1c)) / (int)*(short *)(&DAT_00698110 + iVar3 * 0x24);
    sVar4 = (short)iVar5;
  }
  return (short)local_14 * 100 < local_c[*(int *)(param_1 + 4)] * (int)sVar4;
}

