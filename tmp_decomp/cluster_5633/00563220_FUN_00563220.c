
void FUN_00563220(void)

{
  char *pcVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  char *pcVar5;
  undefined4 *puVar6;
  undefined4 local_180 [96];
  
  pcVar5 = *(char **)(g_pGlobalMapState + 0x1c);
  DAT_006a5aec = 0x6e616461;
  cVar2 = *pcVar5;
  while (cVar2 != '\0') {
    DAT_006a5aec = (DAT_006a5aec >> 0x10) + DAT_006a5aec * 2 + (int)cVar2;
    pcVar1 = pcVar5 + 1;
    pcVar5 = pcVar5 + 1;
    cVar2 = *pcVar1;
  }
  if (DAT_006a5aec == 0) {
    DAT_006a5aec = FUN_005e8ee0(0);
  }
  DAT_006984b8 = 0xffffffff;
  puVar6 = local_180;
  for (iVar4 = 0x60; piVar3 = g_pMapActionContextListHead, iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  for (; piVar3 != (int *)0x0; piVar3 = (int *)piVar3[6]) {
    thunk_GenerateZoneStatusCodeIfUnset();
    (**(code **)(*piVar3 + 0x28))(local_180,0);
  }
  DAT_006a5aec = 0;
  DAT_006a5aec = FUN_005e8ee0(0);
  return;
}

