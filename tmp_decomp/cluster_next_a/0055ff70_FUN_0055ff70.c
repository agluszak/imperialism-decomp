
int FUN_0055ff70(undefined4 param_1,void *param_2,int param_3)

{
  char *pcVar1;
  short sVar2;
  int iVar3;
  void *pvVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = *(int *)(g_pGlobalMapState + 0xc) + (short)param_1 * 0x24;
  if (*(char *)(*(int *)(g_pGlobalMapState + 0xc) + (short)param_1 * 0x24) != '\x05') {
    return 0;
  }
  if (*(char *)(iVar5 + 0x16) != -1) {
    return 0;
  }
  sVar2 = (short)*(char *)(iVar5 + 4);
  iVar5 = 5000;
  if (sVar2 < 0x17) {
    pvVar4 = (void *)0x0;
  }
  else {
    pvVar4 = (void *)(*(int *)(g_pActiveMapContextState + 8) + (sVar2 + -0x17) * 0x48);
  }
  if (pvVar4 != param_2) {
    return 1000;
  }
  iVar6 = 0;
  do {
    sVar2 = thunk_StepHexTileIndexByDirectionWithWrapRules(param_1,iVar6);
    if (sVar2 != -1) {
      pcVar1 = (char *)(*(int *)(g_pGlobalMapState + 0xc) + sVar2 * 0x24);
      if (*pcVar1 == '\x05') {
        pvVar4 = g_pMapActionContextListHead;
        if ((pcVar1[0x16] == '\x03') || (pcVar1[0x16] == '\x0e')) {
          while ((pvVar4 != (void *)0x0 &&
                 (iVar3 = IsNodePresentInLinkedListByNextPointer(&PTR_s_TPortZone_0065c618),
                 iVar3 == 0))) {
            pvVar4 = *(void **)((int)pvVar4 + 0x18);
          }
          for (; pvVar4 != (void *)0x0; pvVar4 = GetNextPortZone(pvVar4)) {
            if (((*(short *)((int)pvVar4 + 0xc) == sVar2) ||
                (*(short *)((int)pvVar4 + 0x20) == sVar2)) ||
               (*(short *)((int)pvVar4 + 0x48) == sVar2)) goto LAB_00560099;
          }
LAB_00560097:
          pvVar4 = (void *)0x0;
        }
        else {
          if (pcVar1[4] < 0x17) goto LAB_00560097;
          pvVar4 = (void *)(*(int *)(g_pActiveMapContextState + 8) +
                           ((short)pcVar1[4] + -0x17) * 0x48);
        }
LAB_00560099:
        if (pvVar4 != param_2) {
          iVar5 = iVar5 + -1;
        }
      }
      else {
        if (*(short *)(pcVar1 + 0x14) == -1) {
          iVar3 = 0;
        }
        else {
          iVar3 = *(int *)(g_pGlobalMapState + 0x10) + *(short *)(pcVar1 + 0x14) * 0xa8;
        }
        if (iVar3 == param_3) {
          iVar5 = iVar5 + 100;
        }
        else {
          iVar5 = iVar5 + -10;
        }
      }
    }
    iVar6 = iVar6 + 1;
    if (5 < iVar6) {
      return iVar5;
    }
  } while( true );
}

