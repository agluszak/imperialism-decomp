
void __fastcall FUN_0055f5c0(int *param_1)

{
  uint uVar1;
  char cVar2;
  void *pvVar3;
  uint uVar4;
  int *piVar5;
  int *piVar6;
  short sVar7;
  
  if ((short)param_1[1] == -1) {
    cVar2 = (**(code **)(*param_1 + 0x38))();
    if (cVar2 == '\0') {
      sVar7 = (short)param_1[0xc];
      if (sVar7 == 2) {
        if ((uint)param_1[0xb] < 2) {
          pvVar3 = ReallocateHeapBlockWithAllocatorTracking();
          if (pvVar3 == (void *)0x0) {
            pvVar3 = ReallocateHeapBlockWithAllocatorTracking();
            param_1[10] = (int)pvVar3;
            param_1[0xb] = 2;
          }
          else {
            param_1[10] = (int)pvVar3;
            param_1[0xb] = 4;
          }
        }
        if ((uint)param_1[0xc] < 2) {
          param_1[0xc] = 2;
        }
        if (param_1[0xb] == 0) {
          pvVar3 = ReallocateHeapBlockWithAllocatorTracking();
          if (pvVar3 == (void *)0x0) {
            pvVar3 = ReallocateHeapBlockWithAllocatorTracking();
            param_1[10] = (int)pvVar3;
            param_1[0xb] = 1;
          }
          else {
            param_1[10] = (int)pvVar3;
            param_1[0xb] = 2;
          }
        }
        if (param_1[0xc] == 0) {
          param_1[0xc] = 1;
        }
        uVar4 = 0;
        uVar1 = *(uint *)(*(int *)param_1[10] + 0x30);
        if (uVar1 != 0) {
          piVar5 = *(int **)(*(int *)param_1[10] + 0x28);
          piVar6 = piVar5;
          do {
            if (*piVar6 == *(int *)(param_1[10] + 4)) {
              piVar5 = piVar5 + uVar4;
              goto LAB_0055f6a9;
            }
            uVar4 = uVar4 + 1;
            piVar6 = piVar6 + 1;
          } while (uVar4 < uVar1);
        }
        piVar5 = (int *)0x0;
LAB_0055f6a9:
        if (piVar5 != (int *)0x0) {
          sVar7 = 1;
        }
      }
      if (sVar7 < 6) {
        if (3 < sVar7) {
          sVar7 = 3;
        }
      }
      else {
        sVar7 = 4;
      }
      if (param_1[0x10] == 0) {
        sVar7 = 4;
      }
      else if (sVar7 == 4) {
        sVar7 = 3;
      }
    }
    else {
      sVar7 = 5;
    }
    DAT_006a5aec = DAT_006a5aec * 0x15a4e35 + 1;
    *(ushort *)(param_1 + 1) = ((ushort)(DAT_006a5aec >> 0xc) & 3) + sVar7 * 4;
  }
  return;
}

