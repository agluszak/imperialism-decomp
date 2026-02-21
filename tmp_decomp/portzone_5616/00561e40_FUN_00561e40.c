
short __fastcall FUN_00561e40(int param_1)

{
  char cVar1;
  bool bVar2;
  short sVar3;
  void *pCurrentPortZone;
  void *pvVar4;
  short sVar5;
  int iVar6;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  int local_4;
  
  local_14 = (int)*(short *)(param_1 + 0xc) / 0x6c;
  local_10 = (int)*(short *)(param_1 + 0xc) % 0x6c;
  local_c = 0;
  local_8 = 5;
  local_4 = 1;
  thunk_FUN_00560470(0);
  if (9 < local_c) {
    return -1;
  }
  do {
    pCurrentPortZone = (void *)0x0;
    if ((((local_14 < 0) || (0x3b < local_14)) || (local_10 < 0)) || (0x6b < local_10)) {
      sVar5 = -1;
    }
    else {
      sVar5 = (short)local_10 + (short)local_14 * 0x6c;
    }
    if ((sVar5 < 0) || (0x194f < sVar5)) {
      bVar2 = false;
    }
    else {
      bVar2 = true;
    }
    if (bVar2) {
      iVar6 = sVar5 * 0x24;
      cVar1 = *(char *)(*(int *)(g_pGlobalMapState + 0xc) + 0x16 + iVar6);
      if ((cVar1 == '\x03') || (cVar1 == '\x0e')) {
        for (pCurrentPortZone = GetFirstPortZone(); pCurrentPortZone != (void *)0x0;
            pCurrentPortZone = GetNextPortZone(pCurrentPortZone)) {
          if (((*(short *)((int)pCurrentPortZone + 0xc) == sVar5) ||
              (*(short *)((int)pCurrentPortZone + 0x20) == sVar5)) ||
             (*(short *)((int)pCurrentPortZone + 0x48) == sVar5)) goto LAB_00561f55;
        }
        pCurrentPortZone = (void *)0x0;
      }
      else {
        sVar3 = (short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + iVar6 + 4);
        if (0x16 < sVar3) {
          pCurrentPortZone =
               (void *)(*(int *)(g_pActiveMapContextState + 8) + (sVar3 + -0x17) * 0x48);
        }
      }
LAB_00561f55:
      if (*(int *)(param_1 + 0x2c) == 0) {
        pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
        if (pvVar4 == (void *)0x0) {
          thunk_FUN_005620c0(1);
        }
        else {
          *(void **)(param_1 + 0x28) = pvVar4;
          *(undefined4 *)(param_1 + 0x2c) = 2;
        }
      }
      if (*(int *)(param_1 + 0x30) == 0) {
        *(undefined4 *)(param_1 + 0x30) = 1;
      }
      if ((pCurrentPortZone == (void *)**(int **)(param_1 + 0x28)) &&
         (*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 0x16 + iVar6) == -1)) {
        return sVar5;
      }
    }
    local_4 = local_4 + 1;
    if (local_c <= local_4) {
      local_4 = 0;
      local_8 = local_8 + 1;
      if (5 < local_8) {
        local_c = local_c + 1;
        local_8 = 0;
        thunk_FUN_0055e550(&local_14,&local_10,4);
      }
    }
    thunk_FUN_0055e550(&local_14,&local_10,local_8);
    if (9 < local_c) {
      return -1;
    }
  } while( true );
}

