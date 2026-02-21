
void __thiscall FUN_0055eba0(int param_1,undefined4 param_2)

{
  uint uVar1;
  void *pvVar2;
  uint uVar3;
  
  uVar1 = *(uint *)(param_1 + 0xc);
  if (*(uint *)(param_1 + 8) <= uVar1) {
    uVar3 = (uVar1 + 1) * 2;
    if (0x7fffffff < uVar3) {
      uVar3 = 0x7fffffff;
    }
    pvVar2 = ReallocateHeapBlockWithAllocatorTracking();
    if (pvVar2 == (void *)0x0) {
      pvVar2 = ReallocateHeapBlockWithAllocatorTracking();
      *(void **)(param_1 + 4) = pvVar2;
      *(uint *)(param_1 + 8) = uVar1 + 1;
    }
    else {
      *(void **)(param_1 + 4) = pvVar2;
      *(uint *)(param_1 + 8) = uVar3;
    }
  }
  if (*(uint *)(param_1 + 0xc) <= uVar1) {
    *(uint *)(param_1 + 0xc) = uVar1 + 1;
  }
  *(undefined4 *)(*(int *)(param_1 + 4) + uVar1 * 4) = param_2;
  return;
}

