
int __thiscall FUN_00555c20(int param_1,int param_2)

{
  int *piVar1;
  uint3 uVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  short sVar6;
  
  uVar3 = 10000;
  for (piVar1 = *(int **)(param_1 + 0x10); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    if (((char)piVar1[3] != '\0') &&
       ((short)*(ushort *)(&DAT_00698124 + *(short *)(*piVar1 + 4) * 0x24) < (short)uVar3)) {
      uVar3 = *(ushort *)(&DAT_00698124 + *(short *)(*piVar1 + 4) * 0x24);
    }
  }
  iVar5 = 0;
  iVar4 = 0;
  for (piVar1 = *(int **)(param_2 + 0x10); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
    if ((char)piVar1[3] != '\0') {
      iVar4 = iVar4 + *(short *)(&DAT_00698124 + *(short *)(*piVar1 + 4) * 0x24);
      iVar5 = iVar5 + 1;
    }
  }
  if (iVar5 == 0) {
    sVar6 = 0;
  }
  else {
    sVar6 = (short)((iVar4 * 10) / iVar5);
  }
  iVar5 = GenerateThreadLocalRandom15();
  sVar6 = ((-(ushort)(uVar3 != 10000) & uVar3) + 5) * 10 - sVar6;
  uVar2 = (uint3)(char)((ushort)sVar6 >> 8);
  if ((int)sVar6 <= iVar5 % 100) {
    return (uint)uVar2 << 8;
  }
  *(undefined1 *)(param_1 + 0x26) = 1;
  return CONCAT31(uVar2,1);
}

