
void __thiscall FUN_0055ed20(int param_1,int *param_2)

{
  void *pvVar1;
  uint uVar2;
  uint uVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uStack_44;
  int iStack_40;
  undefined4 uStack_3c;
  uint uStack_38;
  int aiStack_34 [3];
  int *piStack_28;
  
  piStack_28 = param_2;
  aiStack_34[2] = 0x55ed33;
  thunk_HandleCityDialogNoOpSlot18();
  iVar5 = *param_2;
  aiStack_34[2] = param_1 + 8;
  piStack_28 = (int *)0x20;
  aiStack_34[1] = 0x55ed41;
  (**(code **)(iVar5 + 0x70))();
  pcVar4 = *(code **)(iVar5 + 0x3c);
  aiStack_34[0] = param_1 + 4;
  aiStack_34[1] = 2;
  uStack_38 = 0x55ed52;
  (*pcVar4)();
  uStack_3c = (code *)(param_1 + 0xc);
  uStack_38 = 4;
  iStack_40 = 0x55ed5c;
  (*pcVar4)();
  uStack_44 = (code *)(param_1 + 0x12);
  iStack_40 = 2;
  (*pcVar4)();
  iVar5 = param_1 + 0x20;
  (*pcVar4)(iVar5,2);
  if (DAT_00695278 < 0x12) {
    *(undefined2 *)(param_1 + 0x14) = (undefined2)DAT_006a3fc0;
    DAT_006a3fc0 = DAT_006a3fc0 + 1;
  }
  else {
    (*pcVar4)(param_1 + 0x14,2);
  }
  *(undefined2 *)(param_1 + 0x10) = 0;
  *(undefined2 *)(param_1 + 0x44) = 0;
  iVar6 = *(int *)(param_1 + 0x28);
  if (iVar6 != 0) {
    *(undefined4 *)(param_1 + 0x28) = 0;
    *(undefined4 *)(param_1 + 0x2c) = 0;
    *(undefined4 *)(param_1 + 0x30) = 0;
    FreeHeapBlockWithAllocatorTracking(iVar6);
  }
  iVar6 = *(int *)(param_1 + 0x38);
  if (iVar6 != 0) {
    *(undefined4 *)(param_1 + 0x38) = 0;
    *(undefined4 *)(param_1 + 0x3c) = 0;
    *(undefined4 *)(param_1 + 0x40) = 0;
    FreeHeapBlockWithAllocatorTracking(iVar6);
  }
  if (DAT_00695278 < 0xd) {
    (*pcVar4)((int)&uStack_3c + 2,2);
    iStack_40 = 0;
    if (0 < uStack_44._2_2_) {
      do {
        iVar6 = iStack_40;
        (*pcVar4)(aiStack_34,4);
        uVar3 = (uint)(short)iVar6;
        if (*(uint *)(param_1 + 0x2c) <= uVar3) {
          uStack_38 = (uVar3 + 1) * 2;
          if (0x7fffffff < uStack_38) {
            uStack_38 = 0x7fffffff;
          }
          pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
          if (pvVar1 == (void *)0x0) {
            pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
            *(void **)(param_1 + 0x28) = pvVar1;
            *(uint *)(param_1 + 0x2c) = uVar3 + 1;
          }
          else {
            *(void **)(param_1 + 0x28) = pvVar1;
            *(uint *)(param_1 + 0x2c) = uStack_38;
          }
        }
        if (*(uint *)(param_1 + 0x30) <= uVar3) {
          *(uint *)(param_1 + 0x30) = uVar3 + 1;
        }
        iStack_40 = iStack_40 + 1;
        *(int *)(*(int *)(param_1 + 0x28) + uVar3 * 4) = aiStack_34[0];
        pcVar4 = uStack_3c;
      } while ((short)iStack_40 < uStack_44._2_2_);
    }
    (*pcVar4)((int)&uStack_44 + 2,2);
    iVar6 = 0;
    if (0 < (short)((uint)iVar5 >> 0x10)) {
      do {
        iVar7 = iVar6;
        (*pcVar4)(&uStack_3c,4);
        uVar3 = (uint)(short)iVar6;
        if (*(uint *)(param_1 + 0x3c) <= uVar3) {
          uVar2 = (uVar3 + 1) * 2;
          if (0x7fffffff < uVar2) {
            uVar2 = 0x7fffffff;
          }
          pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
          if (pvVar1 == (void *)0x0) {
            pvVar1 = ReallocateHeapBlockWithAllocatorTracking();
            *(void **)(param_1 + 0x38) = pvVar1;
            *(uint *)(param_1 + 0x3c) = uVar3 + 1;
          }
          else {
            *(void **)(param_1 + 0x38) = pvVar1;
            *(uint *)(param_1 + 0x3c) = uVar2;
          }
        }
        if (*(uint *)(param_1 + 0x40) <= uVar3) {
          *(uint *)(param_1 + 0x40) = uVar3 + 1;
        }
        iVar6 = iVar7 + 1;
        *(code **)(*(int *)(param_1 + 0x38) + uVar3 * 4) = uStack_3c;
        pcVar4 = uStack_44;
      } while ((short)iVar6 < (short)((uint)iVar5 >> 0x10));
    }
  }
  return;
}

