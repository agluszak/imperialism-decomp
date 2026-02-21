
void __thiscall FUN_00556f60(int param_1,int param_2)

{
  int iVar1;
  int *pMapOrderEntry;
  
  while (pMapOrderEntry = *(int **)(param_1 + 4), iVar1 = g_pNavyPrimaryOrderList,
        pMapOrderEntry != (int *)0x0) {
    do {
      if ((short)pMapOrderEntry[7] == param_2) break;
      pMapOrderEntry = (int *)pMapOrderEntry[0xb];
    } while (pMapOrderEntry != (int *)0x0);
    if (pMapOrderEntry == (int *)0x0) break;
    thunk_CancelMapOrderEntryAndRestoreActive(pMapOrderEntry);
  }
  for (; iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x24)) {
    if (*(short *)(iVar1 + 0x14) == param_2) {
      *(undefined4 *)(iVar1 + 0x34) = 0;
    }
  }
  return;
}

