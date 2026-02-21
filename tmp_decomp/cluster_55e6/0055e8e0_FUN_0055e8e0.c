
int * __thiscall FUN_0055e8e0(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  void *pvVar5;
  
  uVar3 = 0;
  uVar1 = *(uint *)(param_1 + 0xc);
  if (uVar1 != 0) {
    piVar4 = *(int **)(param_1 + 4);
    do {
      if (*piVar4 == param_2) {
        piVar4 = *(int **)(param_1 + 4) + uVar3;
        goto LAB_0055e90c;
      }
      uVar3 = uVar3 + 1;
      piVar4 = piVar4 + 1;
    } while (uVar3 < uVar1);
  }
  piVar4 = (int *)0x0;
LAB_0055e90c:
  if (piVar4 == (int *)0x0) {
    if (*(uint *)(param_1 + 8) <= uVar1) {
      uVar3 = (uVar1 + 1) * 2;
      if (0x7fffffff < uVar3) {
        uVar3 = 0x7fffffff;
      }
      pvVar5 = ReallocateHeapBlockWithAllocatorTracking();
      if (pvVar5 == (void *)0x0) {
        pvVar5 = ReallocateHeapBlockWithAllocatorTracking();
        *(void **)(param_1 + 4) = pvVar5;
        *(uint *)(param_1 + 8) = uVar1 + 1;
      }
      else {
        *(void **)(param_1 + 4) = pvVar5;
        *(uint *)(param_1 + 8) = uVar3;
      }
    }
    if (*(uint *)(param_1 + 0xc) <= uVar1) {
      *(uint *)(param_1 + 0xc) = uVar1 + 1;
    }
    iVar2 = *(int *)(param_1 + 4);
    *(int *)(iVar2 + uVar1 * 4) = param_2;
    piVar4 = (int *)(iVar2 + uVar1 * 4);
  }
  return piVar4;
}

