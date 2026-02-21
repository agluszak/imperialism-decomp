
int __thiscall FUN_00553d40(int param_1,int param_2)

{
  short *psVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  
  piVar5 = *(int **)(param_1 + 0x10);
  if (piVar5 == (int *)0x0) {
    piVar5 = (int *)0x0;
  }
  else if (*piVar5 != param_2) {
    piVar5 = FindMissionOrderNodeById((void *)piVar5[1],param_2);
  }
  iVar6 = 0;
  if (piVar5 != (int *)0x0) {
    piVar5 = *(int **)(param_1 + 0x10);
    if (piVar5 != (int *)0x0) {
      if (param_2 == *piVar5) {
        piVar3 = (int *)piVar5[1];
        if (piVar3 != (int *)0x0) {
          piVar3[2] = piVar5[2];
        }
        if (piVar5[2] != 0) {
          *(int *)(piVar5[2] + 4) = piVar5[1];
        }
        FreeHeapBufferIfNotNull(piVar5);
        piVar5 = piVar3;
      }
      else {
        thunk_FUN_005525d0(param_2);
      }
    }
    *(int **)(param_1 + 0x10) = piVar5;
    sVar2 = *(short *)(&DAT_00698120 + *(short *)(param_2 + 4) * 0x24);
    psVar1 = (short *)(param_1 + 0x1e + sVar2 * 2);
    *psVar1 = *psVar1 + -1;
    iVar6 = param_1 + 0x1e + sVar2 * 2;
  }
  if (param_2 == *(int *)(param_1 + 0x14)) {
    iVar4 = *(int *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x14) = 0;
    for (; iVar4 != 0; iVar4 = *(int *)(iVar4 + 4)) {
      iVar6 = thunk_FUN_00550670(*(undefined4 *)(param_1 + 0x14),0);
      *(int *)(param_1 + 0x14) = iVar6;
    }
  }
  *(undefined4 *)(param_2 + 0xc) = 0;
  return iVar6;
}

