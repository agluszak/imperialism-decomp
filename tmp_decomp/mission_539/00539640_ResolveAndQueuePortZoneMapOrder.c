
/* Resolves a port-zone context command into a queued order type.
   
   Behavior:
   1. Build nation bitmask of valid contexts for requested port-zone selector.
   2. Track first matching context whose root node matches active entry context.
   3. If active entry nation mask has no overlap and matching context exists -> queue type 6 with
   that context.
   4. Otherwise queue type 3 (context-zone default path).
   
   Parameters:
   - param_1: Port-zone context selector/message state.
   - param_2: Active map-order entry.
   
   Returns:
   - void. */

void __thiscall ResolveAndQueuePortZoneMapOrder(int param_1,void *param_2)

{
  char cVar1;
  int iVar2;
  void *pvVar3;
  uint uVar4;
  int iVar5;
  int local_8;
  
  thunk_FUN_00552f60(1);
  iVar5 = 0;
  uVar4 = 0;
  local_8 = 0;
  do {
    cVar1 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))
                      (iVar5,*(undefined2 *)(param_1 + 4));
    if (cVar1 != '\0') {
      uVar4 = uVar4 | 1 << ((byte)iVar5 & 0x1f);
      iVar2 = FindFirstPortZoneContextByNation(iVar5);
      if (*(int *)(iVar2 + 0x2c) == 0) {
        pvVar3 = ReallocateHeapBlockWithAllocatorTracking();
        if (pvVar3 == (void *)0x0) {
          pvVar3 = ReallocateHeapBlockWithAllocatorTracking();
          *(void **)(iVar2 + 0x28) = pvVar3;
          *(undefined4 *)(iVar2 + 0x2c) = 1;
        }
        else {
          *(void **)(iVar2 + 0x28) = pvVar3;
          *(undefined4 *)(iVar2 + 0x2c) = 2;
        }
      }
      if (*(int *)(iVar2 + 0x30) == 0) {
        *(undefined4 *)(iVar2 + 0x30) = 1;
      }
      if (**(int **)(iVar2 + 0x28) == *(int *)((int)param_2 + 0x18)) {
        local_8 = FindFirstPortZoneContextByNation(iVar5);
      }
    }
    iVar5 = iVar5 + 1;
  } while (iVar5 < 7);
  if (((*(ushort *)(*(int *)((int)param_2 + 0x18) + 0x10) & (ushort)uVar4) == 0) && (local_8 != 0))
  {
    thunk_SetMapOrderType6AndQueue(param_2,local_8);
    return;
  }
  thunk_SetMapOrderType3Or4AndQueue(param_2,'\0');
  return;
}

