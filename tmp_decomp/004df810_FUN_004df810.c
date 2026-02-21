
void __thiscall FUN_004df810(int param_1,int *param_2)

{
  int *piVar1;
  code *pcVar2;
  int *piVar3;
  char cVar4;
  undefined2 *puVar5;
  int *unaff_EBP;
  int iVar6;
  
  piVar3 = param_2;
  piVar1 = (int *)param_2[0x76];
  if (*(char *)(param_1 + 0xa0) == '\0') {
    param_2 = (int *)0x2;
  }
  else {
    param_2 = *(int **)(g_pLocalizationTable + 0x40);
  }
  pcVar2 = *(code **)(*piVar3 + 0x80);
  iVar6 = 0;
  puVar5 = (undefined2 *)(&DAT_00653570 + (int)param_2 * 0x2e);
  do {
    *(undefined2 *)((int)piVar3 + (short)iVar6 * 2 + 0xb6) = *puVar5;
    (*pcVar2)();
    iVar6 = iVar6 + 1;
    puVar5 = puVar5 + 1;
  } while (iVar6 < 0x17);
  *(short *)(piVar3 + 0x83) = (short)piVar3[0x83] + (999 - (short)piVar3[0x7b]);
  *(undefined2 *)(piVar3 + 0x7b) = 999;
  *(short *)(piVar3 + 0x84) = (short)piVar3[0x84] + (999 - (short)piVar3[0x7c]);
  *(undefined2 *)(piVar3 + 0x7c) = 999;
  *(short *)((int)piVar3 + 0x20e) =
       *(short *)((int)piVar3 + 0x20e) + (999 - *(short *)((int)piVar3 + 0x1ee));
  *(undefined2 *)((int)piVar3 + 0x1ee) = 999;
  *(short *)((int)piVar3 + 0x20a) =
       *(short *)((int)piVar3 + 0x20a) + (999 - *(short *)((int)piVar3 + 0x1ea));
  *(undefined2 *)((int)piVar3 + 0x1ea) = 999;
  *(short *)(piVar3 + 0x86) = (short)piVar3[0x86] + (999 - (short)piVar3[0x7e]);
  *(undefined2 *)(piVar3 + 0x7e) = 999;
  *(short *)((int)piVar3 + 0x216) =
       *(short *)((int)piVar3 + 0x216) + (999 - *(short *)((int)piVar3 + 0x1f6));
  *(undefined2 *)((int)piVar3 + 0x1f6) = 999;
  if (param_2 == (int *)0x0) {
    (**(code **)(*piVar1 + 0x2c))(2,3,2);
  }
  else {
    (**(code **)(*piVar1 + 0x2c))(4,2,1);
  }
  if ((((char)unaff_EBP[0x28] == '\0') || (*(int *)(g_pLocalizationTable + 0x40) < 2)) ||
     (*(short *)(g_pLocalizationTable + 0x114) != 0)) {
    iVar6 = *unaff_EBP;
    cVar4 = (**(code **)(iVar6 + 0xa0))();
    if ((cVar4 == '\0') || (*(short *)(g_pLocalizationTable + 0x114) != 0)) {
      (**(code **)(iVar6 + 0xec))(piVar3);
      return;
    }
  }
  (**(code **)(*unaff_EBP + 0xe8))(piVar3);
  return;
}

