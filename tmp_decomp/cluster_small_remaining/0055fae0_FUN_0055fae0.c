
void __thiscall FUN_0055fae0(int param_1,int param_2)

{
  void *pvVar1;
  uint uVar2;
  
  uVar2 = param_2 * 2;
  if (0x7fffffff < uVar2) {
    uVar2 = 0x7fffffff;
  }
  pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
  if (pvVar1 == (void *)0x0) {
    pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
    *(void **)(param_1 + 4) = pvVar1;
    *(int *)(param_1 + 8) = param_2;
    return;
  }
  *(void **)(param_1 + 4) = pvVar1;
  *(uint *)(param_1 + 8) = uVar2;
  return;
}

