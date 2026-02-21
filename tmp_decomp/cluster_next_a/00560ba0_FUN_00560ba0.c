
void __thiscall FUN_00560ba0(int param_1,int param_2,char param_3)

{
  int iVar1;
  char cVar2;
  short sVar3;
  void *pvVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  sVar3 = (short)param_2;
  if (*(short *)(param_1 + 0x44) <= sVar3) {
    *(short *)(param_1 + 0x44) = sVar3 + 1;
    if (0 < sVar3) {
      iVar5 = *(int *)(param_1 + 0x30);
      uVar8 = iVar5 - 1;
      if (-1 < (int)uVar8) {
        uVar7 = iVar5 * 2;
        do {
          if (param_3 == '\0') {
            if (*(uint *)(param_1 + 0x2c) <= uVar8) {
              uVar6 = uVar7;
              if (0x7fffffff < uVar7) {
                uVar6 = 0x7fffffff;
              }
              pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
              if (pvVar4 == (void *)0x0) {
                pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
                *(void **)(param_1 + 0x28) = pvVar4;
                *(int *)(param_1 + 0x2c) = iVar5;
              }
              else {
                *(void **)(param_1 + 0x28) = pvVar4;
                *(uint *)(param_1 + 0x2c) = uVar6;
              }
            }
            if (*(uint *)(param_1 + 0x30) <= uVar8) {
              *(int *)(param_1 + 0x30) = iVar5;
            }
            cVar2 = (**(code **)(**(int **)(*(int *)(param_1 + 0x28) + uVar8 * 4) + 0x34))();
            if (cVar2 != '\0') goto LAB_00560c58;
          }
          else {
LAB_00560c58:
            if (*(uint *)(param_1 + 0x2c) <= uVar8) {
              uVar6 = uVar7;
              if (0x7fffffff < uVar7) {
                uVar6 = 0x7fffffff;
              }
              pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
              if (pvVar4 == (void *)0x0) {
                pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
                *(void **)(param_1 + 0x28) = pvVar4;
                *(int *)(param_1 + 0x2c) = iVar5;
              }
              else {
                *(void **)(param_1 + 0x28) = pvVar4;
                *(uint *)(param_1 + 0x2c) = uVar6;
              }
            }
            if (*(uint *)(param_1 + 0x30) <= uVar8) {
              *(int *)(param_1 + 0x30) = iVar5;
            }
            thunk_FUN_00560ba0(param_2 + -1,0);
          }
          uVar8 = uVar8 - 1;
          uVar7 = uVar7 - 2;
          iVar5 = iVar5 + -1;
        } while (-1 < (int)uVar8);
      }
    }
    if ((0 < sVar3) && (param_3 != '\0')) {
      iVar5 = *(int *)(param_1 + 0x40);
      uVar8 = iVar5 - 1;
      if (-1 < (int)uVar8) {
        uVar7 = iVar5 * 2;
        do {
          if (*(uint *)(param_1 + 0x3c) <= uVar8) {
            uVar6 = uVar7;
            if (0x7fffffff < uVar7) {
              uVar6 = 0x7fffffff;
            }
            pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
            if (pvVar4 == (void *)0x0) {
              pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
              *(void **)(param_1 + 0x38) = pvVar4;
              *(int *)(param_1 + 0x3c) = iVar5;
            }
            else {
              *(void **)(param_1 + 0x38) = pvVar4;
              *(uint *)(param_1 + 0x3c) = uVar6;
            }
          }
          if (*(uint *)(param_1 + 0x40) <= uVar8) {
            *(int *)(param_1 + 0x40) = iVar5;
          }
          uVar7 = uVar7 - 2;
          iVar1 = uVar8 * 4;
          uVar8 = uVar8 - 1;
          iVar5 = iVar5 + -1;
          *(undefined1 *)(*(int *)(*(int *)(param_1 + 0x38) + iVar1) + 0xa0) = 1;
        } while (-1 < (int)uVar8);
      }
    }
  }
  return;
}

