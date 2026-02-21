
void __fastcall FUN_00539780(int param_1)

{
  int iVar1;
  void *pvVar2;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  undefined2 extraout_var_01;
  undefined2 uVar3;
  
  iVar1 = FindFirstPortZoneContextByNation(*(undefined2 *)(param_1 + 4));
  uVar3 = extraout_var;
  if (*(int *)(iVar1 + 0x2c) == 0) {
    pvVar2 = ReallocateHeapBlockWithAllocatorTracking();
    if (pvVar2 == (void *)0x0) {
      pvVar2 = ReallocateHeapBlockWithAllocatorTracking();
      *(void **)(iVar1 + 0x28) = pvVar2;
      *(undefined4 *)(iVar1 + 0x2c) = 1;
      uVar3 = extraout_var_01;
    }
    else {
      *(void **)(iVar1 + 0x28) = pvVar2;
      *(undefined4 *)(iVar1 + 0x2c) = 2;
      uVar3 = extraout_var_00;
    }
  }
  if (*(int *)(iVar1 + 0x30) == 0) {
    *(undefined4 *)(iVar1 + 0x30) = 1;
  }
  if (**(int **)(iVar1 + 0x28) == *(int *)(param_1 + 0x14)) {
    FindFirstPortZoneContextByNation
              (CONCAT22((short)((uint)*(int *)(param_1 + 0x14) >> 0x10),*(undefined2 *)(param_1 + 4)
                       ));
    return;
  }
  thunk_FUN_00560e70(CONCAT22(uVar3,*(undefined2 *)(param_1 + 4)));
  return;
}

