
void __thiscall FUN_005620c0(int param_1,undefined4 param_2)

{
  void *pvVar1;
  
  pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
  *(undefined4 *)(param_1 + 8) = param_2;
  *(void **)(param_1 + 4) = pvVar1;
  return;
}

