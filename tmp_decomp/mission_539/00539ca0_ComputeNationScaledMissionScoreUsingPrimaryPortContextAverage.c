
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */
/* Computes mission score from primary nation port context average with nation scaling factor
   (fields +0xa4/+0xa6). */

void ComputeNationScaledMissionScoreUsingPrimaryPortContextAverage(void)

{
  double dVar1;
  short sVar2;
  int iVar3;
  void *pvVar4;
  uint uVar5;
  void *pvVar6;
  int in_ECX;
  float local_c;
  int local_4;
  
  if ((&g_apNationStates)[*(short *)(in_ECX + 4)] == 0) {
    sVar2 = 0;
  }
  else {
    sVar2 = *(short *)((&g_apNationStates)[*(short *)(in_ECX + 4)] + 0xa6);
  }
  local_4 = (int)sVar2;
  if (local_4 == 0) {
    local_4 = 1;
  }
  iVar3 = FindFirstPortZoneContextByNation(*(short *)(in_ECX + 4));
  if (*(int *)(iVar3 + 0x2c) == 0) {
    pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
    if (pvVar4 == (void *)0x0) {
      pvVar4 = ReallocateHeapBlockWithAllocatorTracking();
      *(void **)(iVar3 + 0x28) = pvVar4;
      *(undefined4 *)(iVar3 + 0x2c) = 1;
    }
    else {
      *(void **)(iVar3 + 0x28) = pvVar4;
      *(undefined4 *)(iVar3 + 0x2c) = 2;
    }
  }
  if (*(int *)(iVar3 + 0x30) == 0) {
    *(undefined4 *)(iVar3 + 0x30) = 1;
  }
  iVar3 = **(int **)(iVar3 + 0x28);
  uVar5 = thunk_ComputeMapActionContextNodeValueAverage();
  local_c = (float)(int)uVar5;
  for (pvVar4 = GetFirstPortZone(); pvVar4 != (void *)0x0; pvVar4 = GetNextPortZone(pvVar4)) {
    if (*(int *)((int)pvVar4 + 0x2c) == 0) {
      pvVar6 = ReallocateHeapBlockWithAllocatorTracking();
      if (pvVar6 == (void *)0x0) {
        pvVar6 = ReallocateHeapBlockWithAllocatorTracking();
        *(void **)((int)pvVar4 + 0x28) = pvVar6;
        *(undefined4 *)((int)pvVar4 + 0x2c) = 1;
      }
      else {
        *(void **)((int)pvVar4 + 0x28) = pvVar6;
        *(undefined4 *)((int)pvVar4 + 0x2c) = 2;
      }
    }
    if (*(int *)((int)pvVar4 + 0x30) == 0) {
      *(undefined4 *)((int)pvVar4 + 0x30) = 1;
    }
    if (**(int **)((int)pvVar4 + 0x28) == iVar3) {
      sVar2 = thunk_GetPortZoneOwnerNationCodeFromMissionField48();
      dVar1 = _DAT_0065aa18;
      if (sVar2 == *(short *)(in_ECX + 4)) {
        dVar1 = _DAT_0065aa10;
      }
      local_c = local_c * (float)dVar1;
    }
  }
  *(float *)(in_ECX + 0xc) =
       ((local_c / _DAT_0065a9c0) *
       (float)(int)*(short *)((&g_apNationStates)[*(short *)(in_ECX + 4)] + 0xa4)) / (float)local_4;
  return;
}

