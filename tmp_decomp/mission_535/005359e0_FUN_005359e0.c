
undefined4 FUN_005359e0(undefined4 param_1)

{
  byte bVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar6 = (int)(short)param_1;
  bVar1 = *(byte *)(*(int *)(g_pGlobalMapState + 0x10) + iVar6 * 0xa8);
  iVar4 = (**(code **)(*(int *)(&g_pTerrainTypeDescriptorTable)[(short)(char)bVar1] + 0x40))();
  if (iVar4 == iVar6) {
    return 1;
  }
  iVar4 = *(int *)(g_pGlobalMapState + 0x10);
  iVar5 = *(char *)(iVar4 + 8 + iVar6 * 0xa8) + -1;
  if (-1 < iVar5) {
    do {
      sVar3 = (short)*(char *)(iVar4 + *(short *)(iVar4 + 10 +
                                                 ((int)(short)iVar5 + iVar6 * 0x54) * 2) * 0xa8);
      if ((sVar3 < 7) && (sVar3 != (char)bVar1)) {
        return 1;
      }
      iVar5 = iVar5 + -1;
    } while (-1 < iVar5);
  }
  iVar4 = g_pMapActionContextListHead;
  if (g_pMapActionContextListHead == 0) {
    return 0;
  }
  while (((*(ushort *)(iVar4 + 0x10) & ((ushort)(1 << (bVar1 & 0x1f)) ^ 0x7f)) == 0 ||
         (cVar2 = thunk_FUN_0055f440(param_1), cVar2 == '\0'))) {
    iVar4 = *(int *)(iVar4 + 0x18);
    if (iVar4 == 0) {
      return 0;
    }
  }
  return 1;
}

