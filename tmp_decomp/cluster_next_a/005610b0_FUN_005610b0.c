
uint __thiscall FUN_005610b0(int param_1,int param_2)

{
  uint uVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  short sVar5;
  
  if (param_2 == param_1) {
    return 0;
  }
  if ((DAT_006a3fc4 == 0) || (DAT_006a3fc0 != DAT_006984b4)) {
    DAT_006984b4 = DAT_006a3fc0;
    DAT_006a3fc4 = AllocateWithFallbackHandler(DAT_006a3fc0 * DAT_006a3fc0);
    iVar3 = 0;
    if (0 < DAT_006a3fc0 * DAT_006a3fc0) {
      do {
        *(undefined1 *)(iVar3 + DAT_006a3fc4) = 0xff;
        iVar3 = iVar3 + 1;
      } while (iVar3 < DAT_006a3fc0 * DAT_006a3fc0);
    }
  }
  if (param_1 == 0) {
    sVar5 = -1;
  }
  else {
    sVar5 = *(short *)(param_1 + 0x14);
  }
  if (param_2 == 0) {
    sVar2 = -1;
  }
  else {
    sVar2 = *(short *)(param_2 + 0x14);
  }
  uVar4 = (uint)*(char *)((int)sVar2 + DAT_006a3fc4 + sVar5 * DAT_006a3fc0);
  iVar3 = g_pMapActionContextListHead;
  if ((int)uVar4 < 0) {
    for (; iVar3 != 0; iVar3 = *(int *)(iVar3 + 0x18)) {
      *(undefined2 *)(iVar3 + 0x44) = 0x29a;
    }
    iVar3 = g_pMapActionContextListHead;
    if (0 < *(short *)(param_1 + 0x44)) {
      *(undefined2 *)(param_1 + 0x44) = 0;
      uVar4 = *(uint *)(param_1 + 0x30);
      uVar1 = uVar4;
      while (uVar1 = uVar1 - 1, iVar3 = g_pMapActionContextListHead, -1 < (int)uVar1) {
        if (*(uint *)(param_1 + 0x2c) <= uVar1) {
          thunk_ResizePointerArrayCapacityByRequestedCountAlt(uVar4);
        }
        if (*(uint *)(param_1 + 0x30) <= uVar1) {
          *(uint *)(param_1 + 0x30) = uVar4;
        }
        thunk_FUN_00560f80(1);
        uVar4 = uVar4 - 1;
      }
    }
    for (; iVar3 != 0; iVar3 = *(int *)(iVar3 + 0x18)) {
      if (param_1 == 0) {
        sVar5 = -1;
      }
      else {
        sVar5 = *(short *)(param_1 + 0x14);
      }
      if (iVar3 == 0) {
        sVar2 = -1;
      }
      else {
        sVar2 = *(short *)(iVar3 + 0x14);
      }
      *(undefined1 *)((int)sVar2 + DAT_006a3fc4 + sVar5 * DAT_006a3fc0) =
           *(undefined1 *)(iVar3 + 0x44);
      if (iVar3 == 0) {
        sVar5 = -1;
      }
      else {
        sVar5 = *(short *)(iVar3 + 0x14);
      }
      if (param_1 == 0) {
        sVar2 = -1;
      }
      else {
        sVar2 = *(short *)(param_1 + 0x14);
      }
      *(undefined1 *)((int)sVar2 + DAT_006a3fc4 + sVar5 * DAT_006a3fc0) =
           *(undefined1 *)(iVar3 + 0x44);
    }
    if (param_1 == 0) {
      sVar5 = -1;
    }
    else {
      sVar5 = *(short *)(param_1 + 0x14);
    }
    if (param_2 == 0) {
      sVar2 = -1;
    }
    else {
      sVar2 = *(short *)(param_2 + 0x14);
    }
    uVar4 = (uint)*(char *)((int)sVar2 + DAT_006a3fc4 + sVar5 * DAT_006a3fc0);
  }
  return uVar4 & 0xffff;
}

