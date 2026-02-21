
int __thiscall FUN_00558860(int param_1,uint param_2)

{
  void *pvVar1;
  uint uVar2;
  
  if (*(uint *)(param_1 + 8) <= param_2) {
    uVar2 = (param_2 + 1) * 2;
    if (0x7fffffff < uVar2) {
      uVar2 = 0x7fffffff;
    }
    pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
    if (pvVar1 == (void *)0x0) {
      pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
      *(void **)(param_1 + 4) = pvVar1;
      *(uint *)(param_1 + 8) = param_2 + 1;
    }
    else {
      *(void **)(param_1 + 4) = pvVar1;
      *(uint *)(param_1 + 8) = uVar2;
    }
  }
  if (*(uint *)(param_1 + 0xc) <= param_2) {
    *(uint *)(param_1 + 0xc) = param_2 + 1;
  }
  return *(int *)(param_1 + 4) + param_2 * 4;
}

