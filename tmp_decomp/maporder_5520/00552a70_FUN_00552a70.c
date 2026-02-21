
void __thiscall FUN_00552a70(int param_1,undefined2 param_2,undefined4 param_3)

{
  short *psVar1;
  int nChildNodeId;
  int *piVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  
  piVar4 = *(int **)(param_1 + 0x10);
  while (piVar4 != (int *)0x0) {
    nChildNodeId = *piVar4;
    if (piVar4 == (int *)0x0) {
      piVar4 = (int *)0x0;
    }
    else if (*piVar4 != nChildNodeId) {
      piVar4 = FindMissionOrderNodeById((void *)piVar4[1],nChildNodeId);
    }
    if (piVar4 != (int *)0x0) {
      piVar4 = *(int **)(param_1 + 0x10);
      if (piVar4 == (int *)0x0) {
        piVar4 = (int *)0x0;
      }
      else if (nChildNodeId == *piVar4) {
        piVar2 = (int *)piVar4[1];
        if (piVar2 != (int *)0x0) {
          piVar2[2] = piVar4[2];
        }
        if (piVar4[2] != 0) {
          *(int *)(piVar4[2] + 4) = piVar4[1];
        }
        FreeHeapBufferIfNotNull(piVar4);
        piVar4 = piVar2;
      }
      else {
        thunk_FUN_005525d0(nChildNodeId);
      }
      *(int **)(param_1 + 0x10) = piVar4;
      psVar1 = (short *)(param_1 + 0x1e +
                        *(short *)(&DAT_00698120 + *(short *)(nChildNodeId + 4) * 0x24) * 2);
      *psVar1 = *psVar1 + -1;
    }
    if (nChildNodeId == *(int *)(param_1 + 0x14)) {
      iVar3 = *(int *)(param_1 + 0x10);
      *(undefined4 *)(param_1 + 0x14) = 0;
      for (; iVar3 != 0; iVar3 = *(int *)(iVar3 + 4)) {
        uVar5 = thunk_FUN_00550670(*(undefined4 *)(param_1 + 0x14),0);
        *(undefined4 *)(param_1 + 0x14) = uVar5;
      }
    }
    *(undefined4 *)(nChildNodeId + 0xc) = 0;
    piVar4 = *(int **)(param_1 + 0x10);
  }
  *(undefined2 *)(param_1 + 0x1c) = param_2;
  *(undefined4 *)(param_1 + 0x18) = param_3;
  return;
}

