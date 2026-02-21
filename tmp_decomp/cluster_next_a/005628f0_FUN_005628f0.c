
void __thiscall FUN_005628f0(code *param_1,int *param_2)

{
  code *pcVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  code *unaff_EDI;
  code *pcVar7;
  code *pcVar8;
  code *pcVar9;
  code *pcVar10;
  
  thunk_HandleCityDialogNoOpSlot14(param_2);
  pcVar10 = param_1 + 4;
  pcVar9 = pcVar10;
  (**(code **)(*param_2 + 0x78))(pcVar10,2);
  iVar4 = 0;
  if (0 < *(short *)pcVar10) {
    iVar3 = 0;
    do {
      (**(code **)(*(int *)(*(int *)(param_1 + 8) + iVar3) + 0x14))(param_2);
      iVar4 = iVar4 + 1;
      iVar3 = iVar3 + 0x48;
    } while (iVar4 < *(short *)(param_1 + 4));
  }
  pcVar10 = (code *)0x0;
  piVar6 = g_pMapActionContextListHead;
  if (g_pMapActionContextListHead != (int *)0x0) {
    do {
      iVar4 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618);
      if (iVar4 != 0) break;
      piVar6 = (int *)piVar6[6];
    } while (piVar6 != (int *)0x0);
joined_r0x0056295f:
    if (piVar6 != (int *)0x0) {
      pcVar10 = pcVar10 + 1;
      piVar6 = (int *)piVar6[6];
      if (piVar6 == (int *)0x0) goto LAB_0056298c;
      do {
        iVar4 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618);
        if (iVar4 != 0) break;
        piVar6 = (int *)piVar6[6];
      } while (piVar6 != (int *)0x0);
      goto joined_r0x0056295f;
    }
  }
LAB_0056298c:
  pcVar8 = (code *)&stack0xfffffff4;
  (*param_1)(pcVar8,2);
  piVar6 = g_pMapActionContextListHead;
  while ((piVar5 = piVar6, piVar6 != (int *)0x0 &&
         (iVar4 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618), iVar4 == 0))) {
    piVar6 = (int *)piVar6[6];
  }
  do {
    piVar2 = piVar5;
    if ((piVar2 == (int *)0x0) || (piVar5 = (int *)piVar2[6], piVar6 = piVar2, piVar5 == (int *)0x0)
       ) break;
    do {
      iVar4 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618);
      if (iVar4 != 0) break;
      piVar5 = (int *)piVar5[6];
    } while (piVar5 != (int *)0x0);
  } while( true );
joined_r0x005629ea:
  if (piVar6 == (int *)0x0) {
LAB_00562a16:
    pcVar1 = param_1 + 0xc;
    pcVar7 = pcVar1;
    (*pcVar10)(pcVar1,2);
    iVar4 = 0;
    if (0 < *(short *)pcVar1) {
      iVar3 = 0;
      do {
        (*unaff_EDI)(iVar3 + 4 + *(int *)(param_1 + 0x10),4);
        (*pcVar9)(iVar3 + *(int *)(param_1 + 0x10),4);
        (*pcVar8)(iVar3 + 0xc + *(int *)(param_1 + 0x10),4);
        (*pcVar7)(iVar3 + 8 + *(int *)(param_1 + 0x10),4);
        iVar4 = iVar4 + 1;
        iVar3 = iVar3 + 0x10;
      } while (iVar4 < *(short *)(param_1 + 0xc));
    }
    return;
  }
  (**(code **)(*piVar6 + 0x14))(param_2);
  piVar6 = (int *)piVar6[7];
  if (piVar6 == (int *)0x0) goto LAB_00562a16;
  do {
    iVar4 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618);
    if (iVar4 != 0) break;
    piVar6 = (int *)piVar6[7];
  } while (piVar6 != (int *)0x0);
  goto joined_r0x005629ea;
}

