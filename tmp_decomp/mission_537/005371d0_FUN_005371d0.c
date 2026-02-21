
void __fastcall FUN_005371d0(int param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  int *pMapOrderEntry;
  
  for (puVar1 = *(undefined4 **)(param_1 + 0x24); puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)puVar1[1]) {
    if (*(char *)(puVar1 + 3) == '\0') {
      *(undefined1 *)(puVar1 + 3) = 1;
      pMapOrderEntry = GetOrCreateMissionOrderEntryForNode((void *)*puVar1);
      for (piVar2 = *(int **)(param_1 + 0x24); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[1]) {
        if (((char)piVar2[3] == '\0') && (*(int *)(*piVar2 + 8) == pMapOrderEntry[6])) {
          ObjectPool__RemoveNode((void *)*piVar2,(int)pMapOrderEntry);
          *(undefined1 *)(piVar2 + 3) = 1;
        }
      }
      PromoteMapOrderChainAndQueue(pMapOrderEntry);
    }
  }
  return;
}

