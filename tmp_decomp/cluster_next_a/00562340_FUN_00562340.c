
void __thiscall FUN_00562340(int param_1,int *param_2)

{
  short *psVar1;
  code *pcVar2;
  short sVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  int unaff_EBP;
  int unaff_ESI;
  int iVar7;
  int unaff_EDI;
  int *unaff_FS_OFFSET;
  int iVar8;
  undefined1 *puVar9;
  short *psVar10;
  short *psStack_14;
  int *piStack_c;
  undefined1 *puStack_8;
  short *psStack_4;
  
  psStack_4 = (short *)0xffffffff;
  puStack_8 = &LAB_00635855;
  piStack_c = (int *)*unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int)&piStack_c;
  if (DAT_006a3fc4 != 0) {
    FreeHeapBufferIfNotNull(DAT_006a3fc4);
    DAT_006a3fc4 = 0;
    DAT_006a3fc0 = 0xffffffff;
  }
  thunk_HandleCityDialogNoOpSlot18(param_2);
  thunk_FUN_00564600(0);
  psVar1 = (short *)(param_1 + 4);
  iVar6 = 0;
  if (0 < *psVar1) {
    iVar7 = 0;
    do {
      piVar4 = (int *)(iVar7 + *(int *)(param_1 + 8));
      if (g_pMapActionContextListHead == piVar4) {
        g_pMapActionContextListHead = (int *)piVar4[6];
      }
      if (piVar4[6] != 0) {
        *(int *)(piVar4[6] + 0x1c) = piVar4[7];
      }
      if (piVar4[7] != 0) {
        *(int *)(piVar4[7] + 0x18) = piVar4[6];
      }
      piVar4[7] = 0;
      piVar4[6] = 0;
      iVar6 = iVar6 + 1;
      iVar7 = iVar7 + 0x48;
    } while (iVar6 < *psVar1);
  }
  if (*(int **)(param_1 + 8) != (int *)0x0) {
    (**(code **)(**(int **)(param_1 + 8) + 4))(3);
  }
  while (piVar4 = g_pMapActionContextListHead, g_pMapActionContextListHead != (int *)0x0) {
    do {
      iVar6 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618);
      if (iVar6 != 0) break;
      piVar4 = (int *)piVar4[6];
    } while (piVar4 != (int *)0x0);
    piVar5 = g_pMapActionContextListHead;
    if (piVar4 == (int *)0x0) break;
    while ((piVar5 != (int *)0x0 &&
           (iVar6 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618), iVar6 == 0)))
    {
      piVar5 = (int *)piVar5[6];
    }
    (**(code **)(*piVar5 + 0x1c))();
  }
  pcVar2 = *(code **)(*param_2 + 0x3c);
  psVar10 = psVar1;
  (*pcVar2)(psVar1,2);
  iVar6 = (int)*psVar1;
  piVar4 = (int *)AllocateWithFallbackHandler(iVar6 * 0x48 + 4);
  piStack_c = (int *)0x0;
  if (piVar4 == (int *)0x0) {
    piVar5 = (int *)0x0;
  }
  else {
    piVar5 = piVar4 + 1;
    *piVar4 = iVar6;
    CallCallbackRepeatedly
              (piVar5,0x48,iVar6,thunk_ConstructTZoneAndLinkIntoGlobalMapActionContextList);
  }
  iVar6 = 0;
  piStack_c = (int *)0xffffffff;
  *(int **)(unaff_EBP + 8) = piVar5;
  if (piVar5 == (int *)0x0) {
                    /* WARNING: Subroutine does not return */
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  iVar7 = 0;
  if (0 < *psStack_4) {
    do {
      (**(code **)(*(int *)(*(int *)(unaff_EBP + 8) + iVar6) + 0x18))(param_2);
      iVar7 = iVar7 + 1;
      iVar6 = iVar6 + 0x48;
    } while (iVar7 < *psStack_4);
  }
  puVar9 = &stack0xffffffe4;
  (*pcVar2)(puVar9,2);
  sVar3 = (short)unaff_ESI;
  while (unaff_ESI = unaff_ESI + -1, sVar3 != 0) {
    piVar4 = (int *)AllocateWithFallbackHandler(0x4c);
    piStack_c = piVar4;
    if (piVar4 == (int *)0x0) {
      piVar4 = (int *)0x0;
    }
    else {
      thunk_ConstructTZoneAndLinkIntoGlobalMapActionContextList();
      *(undefined2 *)(piVar4 + 0x12) = 0xffff;
      *piVar4 = (int)&PTR_thunk_GetTPortZoneClassName_0065c758;
    }
    psStack_14 = (short *)0xffffffff;
    (**(code **)(*piVar4 + 0x18))(param_2);
    sVar3 = (short)unaff_ESI;
  }
  piVar4 = (int *)(unaff_EDI + 0xc);
  piVar5 = piVar4;
  piStack_c = piVar4;
  (*pcVar2)(piVar4,2);
  FreeHeapBufferIfNotNull(*(undefined4 *)(unaff_EDI + 0x10));
  iVar6 = AllocateWithFallbackHandler((int)*(short *)piVar4 << 4);
  if (iVar6 == 0) {
    iVar6 = 0;
  }
  *(int *)(psVar10 + 8) = iVar6;
  if (iVar6 == 0) {
                    /* WARNING: Subroutine does not return */
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  iVar6 = 0;
  if (0 < *(short *)piVar4) {
    iVar7 = 0;
    do {
      iVar8 = iVar7 + 4 + *(int *)(psVar10 + 8);
      (*pcVar2)(iVar8,4);
      (*pcVar2)(iVar7 + *(int *)(puVar9 + 0x10),4);
      (*pcVar2)(iVar7 + 0xc + piVar5[4],4);
      (*pcVar2)(iVar7 + 8 + *(int *)(iVar8 + 0x10),4);
      iVar6 = iVar6 + 1;
      iVar7 = iVar7 + 0x10;
    } while (iVar6 < *psStack_14);
  }
  piVar4 = g_pMapActionContextListHead;
  if (DAT_00695278 < 0xd) {
    for (; piVar4 != (int *)0x0; piVar4 = (int *)piVar4[6]) {
      iVar6 = piVar4[10];
      if (iVar6 != 0) {
        piVar4[10] = 0;
        piVar4[0xb] = 0;
        piVar4[0xc] = 0;
        FreeHeapBlockWithAllocatorTracking(iVar6);
      }
      iVar6 = piVar4[0xe];
      if (iVar6 != 0) {
        piVar4[0xe] = 0;
        piVar4[0xf] = 0;
        piVar4[0x10] = 0;
        FreeHeapBlockWithAllocatorTracking(iVar6);
      }
    }
  }
  thunk_FUN_00563f50();
  *unaff_FS_OFFSET = unaff_ESI;
  return;
}

