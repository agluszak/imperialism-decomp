
void __fastcall FUN_004dd270(int *param_1)

{
  code *pcVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  short *psVar6;
  int iVar7;
  
  iVar7 = 0;
  piVar5 = param_1 + 0xa0;
  pcVar1 = *(code **)(*param_1 + 0x78);
  psVar6 = (short *)((int)param_1 + 0x1c6);
  do {
    *psVar6 = psVar6[0x45];
    if (psVar6[0x45] == -1) {
      *(short *)(param_1 + 0x2c) = (short)param_1[0x2c] + 1;
    }
    sVar2 = (*pcVar1)(iVar7);
    if (sVar2 < *psVar6) {
      sVar2 = (*pcVar1)(iVar7);
      *psVar6 = sVar2;
    }
    iVar4 = 0x10;
    piVar3 = piVar5;
    do {
      *piVar3 = 0;
      piVar3 = piVar3 + 0x17;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    iVar7 = iVar7 + 1;
    psVar6 = psVar6 + 1;
    piVar5 = piVar5 + 1;
  } while ((short)iVar7 < 0x17);
  return;
}

