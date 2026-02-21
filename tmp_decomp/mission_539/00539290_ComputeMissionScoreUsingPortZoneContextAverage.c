
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */
/* Computes mission score from map-action context node-value average and port-zone owner match (no
   +0x11 clear). */

void ComputeMissionScoreUsingPortZoneContextAverage(void)

{
  int iVar1;
  double dVar2;
  short sVar3;
  uint uVar4;
  void *pCurrentPortZone;
  void *pvVar5;
  int in_ECX;
  float local_4;
  
  iVar1 = *(int *)(in_ECX + 0x14);
  uVar4 = thunk_ComputeMapActionContextNodeValueAverage();
  local_4 = (float)(int)uVar4;
  for (pCurrentPortZone = GetFirstPortZone(); pCurrentPortZone != (void *)0x0;
      pCurrentPortZone = GetNextPortZone(pCurrentPortZone)) {
    if (*(int *)((int)pCurrentPortZone + 0x2c) == 0) {
      pvVar5 = ReallocateHeapBlockWithAllocatorTracking();
      if (pvVar5 == (void *)0x0) {
        pvVar5 = ReallocateHeapBlockWithAllocatorTracking();
        *(void **)((int)pCurrentPortZone + 0x28) = pvVar5;
        *(undefined4 *)((int)pCurrentPortZone + 0x2c) = 1;
      }
      else {
        *(void **)((int)pCurrentPortZone + 0x28) = pvVar5;
        *(undefined4 *)((int)pCurrentPortZone + 0x2c) = 2;
      }
    }
    if (*(int *)((int)pCurrentPortZone + 0x30) == 0) {
      *(undefined4 *)((int)pCurrentPortZone + 0x30) = 1;
    }
    if (**(int **)((int)pCurrentPortZone + 0x28) == iVar1) {
      sVar3 = thunk_GetPortZoneOwnerNationCodeFromMissionField48();
      dVar2 = _DAT_0065aa18;
      if (sVar3 == *(short *)(in_ECX + 4)) {
        dVar2 = _DAT_0065aa10;
      }
      local_4 = local_4 * (float)dVar2;
    }
  }
  *(float *)(in_ECX + 0xc) = local_4 / _DAT_0065a9c0;
  return;
}

