
undefined4 __thiscall FUN_00561510(int param_1,undefined4 param_2)

{
  bool bVar1;
  char cVar2;
  void *pvVar3;
  uint uVar4;
  int iVar5;
  
  uVar4 = 0;
  for (pvVar3 = thunk_GetNavyPrimaryOrderListHead(); pvVar3 != (void *)0x0;
      pvVar3 = *(void **)((int)pvVar3 + 0x24)) {
    if (((*(int *)((int)pvVar3 + 8) == param_1) && (iVar5 = *(int *)((int)pvVar3 + 0xc), iVar5 != 0)
        ) && (*(char *)(iVar5 + 0x26) == '\0')) {
      if ((*(int *)(iVar5 + 8) == 3) || (*(int *)(iVar5 + 8) == 4)) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
      if (bVar1) {
        uVar4 = uVar4 | 1 << (*(byte *)((int)pvVar3 + 0x14) & 0x1f);
      }
    }
  }
  if ((uVar4 & 1 << ((byte)param_2 & 0x1f)) != 0) {
    return 0;
  }
  iVar5 = 0;
  while (((uVar4 & 1 << ((byte)iVar5 & 0x1f)) == 0 ||
         (cVar2 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))(iVar5,param_2),
         cVar2 == '\0'))) {
    iVar5 = iVar5 + 1;
    if (6 < iVar5) {
      return 0;
    }
  }
  return 1;
}

