
int * __thiscall FUN_00553bc0(int *param_1,int param_2)

{
  short *psVar1;
  short sVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  
  piVar3 = (int *)param_1[4];
  if (piVar3 == (int *)0x0) {
    piVar3 = (int *)0x0;
  }
  else if (*piVar3 != param_2) {
    piVar3 = FindMissionOrderNodeById((void *)piVar3[1],param_2);
  }
  if (piVar3 == (int *)0x0) {
    piVar3 = (int *)param_1[4];
    piVar6 = (int *)0x0;
    if (piVar3 != (int *)0x0) {
      piVar4 = piVar3;
      do {
        piVar3 = piVar4;
        if (*(short *)(&DAT_00698120 + *(short *)(param_2 + 4) * 0x24) <=
            *(short *)(&DAT_00698120 + *(short *)(*piVar4 + 4) * 0x24)) break;
        piVar3 = (int *)piVar4[1];
        piVar6 = piVar4;
        piVar4 = piVar3;
      } while (piVar3 != (int *)0x0);
    }
    piVar4 = (int *)AllocateWithFallbackHandler(0x10);
    if (piVar4 == (int *)0x0) {
      piVar4 = (int *)0x0;
    }
    else {
      *piVar4 = param_2;
      piVar4[1] = (int)piVar3;
      piVar4[2] = (int)piVar6;
      *(undefined1 *)(piVar4 + 3) = 1;
      if (piVar3 != (int *)0x0) {
        piVar3[2] = (int)piVar4;
      }
      if (piVar4[2] != 0) {
        *(int **)(piVar4[2] + 4) = piVar4;
      }
    }
    if (piVar4 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
      MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
    }
    if (piVar3 == (int *)param_1[4]) {
      param_1[4] = (int)piVar4;
    }
    iVar5 = thunk_FUN_00550670(param_1[5],0);
    param_1[5] = iVar5;
    sVar2 = *(short *)(&DAT_00698120 + *(short *)(param_2 + 4) * 0x24);
    psVar1 = (short *)((int)param_1 + sVar2 * 2 + 0x1e);
    *psVar1 = *psVar1 + 1;
    *(int **)(param_2 + 0xc) = param_1;
    piVar3 = (int *)((int)param_1 + sVar2 * 2 + 0x1e);
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 0xc))();
      piVar3 = (int *)param_1[1];
      *(int **)(param_2 + 0x10) = piVar3;
      sVar2 = (short)param_1[2];
      if ((((sVar2 != 0) && (sVar2 != 7)) && (sVar2 != 8)) && (sVar2 != 4)) {
        *(undefined4 *)(param_2 + 0x34) = 0;
      }
    }
  }
  return piVar3;
}

