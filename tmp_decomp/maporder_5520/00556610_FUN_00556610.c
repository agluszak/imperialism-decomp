
void FUN_00556610(void)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  undefined2 *puVar5;
  short *psVar6;
  
  iVar3 = 0;
  puVar5 = &DAT_006a3e28;
  do {
    uVar2 = (undefined2)iVar3;
    *puVar5 = uVar2;
    (&DAT_006a3e90)[iVar3] = uVar2;
    (&DAT_006a3e50)[iVar3] = uVar2;
    puVar5 = puVar5 + 1;
    iVar3 = iVar3 + 1;
  } while ((int)puVar5 < 0x6a3e44);
  psVar6 = &DAT_006a3e28;
  iVar3 = 0;
  do {
    if (iVar3 + 1 < 0xe) {
      iVar4 = iVar3 * 2 + 2;
      do {
        if ((int)(&DAT_00698118)[(short)(&DAT_006a3e90)[iVar3] * 9] <
            (int)(&DAT_00698118)[*(short *)((int)&DAT_006a3e90 + iVar4) * 9]) {
          uVar2 = (&DAT_006a3e90)[iVar3];
          (&DAT_006a3e90)[iVar3] = *(short *)((int)&DAT_006a3e90 + iVar4);
          *(undefined2 *)((int)&DAT_006a3e90 + iVar4) = uVar2;
        }
        if ((int)(&DAT_0069810c)[(short)(&DAT_006a3e50)[iVar3] * 9] <
            (int)(&DAT_0069810c)[*(short *)((int)&DAT_006a3e50 + iVar4) * 9]) {
          uVar2 = (&DAT_006a3e50)[iVar3];
          (&DAT_006a3e50)[iVar3] = *(short *)((int)&DAT_006a3e50 + iVar4);
          *(undefined2 *)((int)&DAT_006a3e50 + iVar4) = uVar2;
        }
        sVar1 = *psVar6;
        if ((int)(&DAT_00698108)[sVar1 * 9] <
            (int)(&DAT_00698108)[*(short *)((int)&DAT_006a3e28 + iVar4) * 9]) {
          *psVar6 = *(short *)((int)&DAT_006a3e28 + iVar4);
          *(short *)((int)&DAT_006a3e28 + iVar4) = sVar1;
        }
        iVar4 = iVar4 + 2;
      } while (iVar4 < 0x1c);
    }
    psVar6 = psVar6 + 1;
    iVar3 = iVar3 + 1;
  } while ((int)psVar6 < 0x6a3e42);
  return;
}

