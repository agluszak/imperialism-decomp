
void __thiscall FUN_00560f80(int param_1,int param_2)

{
  void *pvVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint local_8;
  
  iVar2 = g_pMapActionContextListHead;
  if ((short)param_2 == -1) {
    for (; iVar2 != 0; iVar2 = *(int *)(iVar2 + 0x18)) {
      *(undefined2 *)(iVar2 + 0x44) = 0x29a;
    }
    param_2 = 0;
  }
  if ((short)param_2 < *(short *)(param_1 + 0x44)) {
    *(short *)(param_1 + 0x44) = (short)param_2;
    iVar2 = *(int *)(param_1 + 0x30);
    uVar4 = iVar2 - 1;
    if (-1 < (int)uVar4) {
      uVar3 = iVar2 * 2;
      do {
        if (*(uint *)(param_1 + 0x2c) <= uVar4) {
          local_8 = uVar3;
          if (0x7fffffff < uVar3) {
            local_8 = 0x7fffffff;
          }
          pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
          if (pvVar1 == (void *)0x0) {
            pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
            *(void **)(param_1 + 0x28) = pvVar1;
            *(int *)(param_1 + 0x2c) = iVar2;
          }
          else {
            *(void **)(param_1 + 0x28) = pvVar1;
            *(uint *)(param_1 + 0x2c) = local_8;
          }
        }
        if (*(uint *)(param_1 + 0x30) <= uVar4) {
          *(int *)(param_1 + 0x30) = iVar2;
        }
        thunk_FUN_00560f80(param_2 + 1);
        uVar4 = uVar4 - 1;
        uVar3 = uVar3 - 2;
        iVar2 = iVar2 + -1;
      } while (-1 < (int)uVar4);
    }
  }
  return;
}

