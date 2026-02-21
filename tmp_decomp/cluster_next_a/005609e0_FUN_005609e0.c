
undefined4 __thiscall FUN_005609e0(int param_1,undefined4 param_2)

{
  short sVar1;
  void *pvVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_c = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack_8 = &LAB_006357ca;
  *unaff_FS_OFFSET = &local_c;
  sVar1 = (short)param_2;
  if (sVar1 == -1) {
    sVar1 = thunk_GetActiveNationId();
  }
  if ((*(byte *)(param_1 + 0x10) & '\x01' << ((byte)sVar1 & 0x1f)) != 0) {
    for (pvVar2 = thunk_GetNavyPrimaryOrderListHead(); pvVar2 != (void *)0x0;
        pvVar2 = *(void **)((int)pvVar2 + 0x24)) {
      if (((*(int *)((int)pvVar2 + 8) == param_1) && (*(short *)((int)pvVar2 + 0x14) == sVar1)) &&
         (*(int *)((int)pvVar2 + 0xc) == 0)) {
        iVar3 = AllocateWithFallbackHandler(0x34);
        local_4 = 0;
        if (iVar3 == 0) {
          uVar4 = 0;
        }
        else {
          uVar4 = thunk_ConstructTTaskForce(param_1,param_2);
        }
        local_4 = 0xffffffff;
        thunk_NoOpTaskForceVtableSlot();
        thunk_RefreshTaskForceSelectionFlagsForCurrentNationOrders(0);
        thunk_RecomputeTaskForceAverageOrderScore();
        *unaff_FS_OFFSET = local_c;
        return uVar4;
      }
    }
  }
  *unaff_FS_OFFSET = local_c;
  return 0;
}

