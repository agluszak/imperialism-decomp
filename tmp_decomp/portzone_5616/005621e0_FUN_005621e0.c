
void __fastcall FUN_005621e0(int *param_1)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  if (g_pNavyOrderManager != 0) {
    thunk_ResetPrimaryOrderActiveFlagsAndClearManagerState();
  }
  if (DAT_006a3fc4 != 0) {
    FreeHeapBufferIfNotNull(DAT_006a3fc4);
    DAT_006a3fc4 = 0;
    DAT_006984b4 = 0xffffffff;
    DAT_006a3fc0 = 0;
  }
  iVar3 = 0;
  if (0 < (short)param_1[1]) {
    iVar4 = 0;
    do {
      piVar2 = (int *)(param_1[2] + iVar4);
      if (g_pMapActionContextListHead == piVar2) {
        g_pMapActionContextListHead = (int *)piVar2[6];
      }
      if (piVar2[6] != 0) {
        *(int *)(piVar2[6] + 0x1c) = piVar2[7];
      }
      if (piVar2[7] != 0) {
        *(int *)(piVar2[7] + 0x18) = piVar2[6];
      }
      piVar2[7] = 0;
      piVar2[6] = 0;
      iVar3 = iVar3 + 1;
      iVar4 = iVar4 + 0x48;
    } while (iVar3 < (short)param_1[1]);
  }
  if ((int *)param_1[2] != (int *)0x0) {
    (**(code **)(*(int *)param_1[2] + 4))(3);
  }
  while (piVar2 = g_pMapActionContextListHead, g_pMapActionContextListHead != (int *)0x0) {
    do {
      iVar3 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618);
      if (iVar3 != 0) break;
      piVar2 = (int *)piVar2[6];
    } while (piVar2 != (int *)0x0);
    piVar1 = g_pMapActionContextListHead;
    if (piVar2 == (int *)0x0) break;
    while ((piVar1 != (int *)0x0 &&
           (iVar3 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618), iVar3 == 0)))
    {
      piVar1 = (int *)piVar1[6];
    }
    (**(code **)(*piVar1 + 0x1c))();
  }
  FreeHeapBufferIfNotNull(param_1[4]);
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + 4))(1);
  }
  return;
}

