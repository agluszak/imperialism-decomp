
void __fastcall FUN_004dbd20(int *param_1)

{
  char cVar1;
  char cVar2;
  short sVar3;
  char *pcVar4;
  int *piVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  short *psVar11;
  int local_10;
  char *local_c;
  
  puVar9 = (undefined4 *)((int)param_1 + 0x10e);
  for (iVar6 = 0xb; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  *(undefined2 *)puVar9 = 0;
  pcVar4 = BuildCityInfluenceLevelMap(param_1);
  iVar6 = 0;
  local_10 = 0;
  piVar7 = g_pGlobalMapState;
  local_c = pcVar4;
  do {
    cVar1 = *local_c;
    if (cVar1 != '\0') {
      if (*(char *)(piVar7[3] + 0x13 + iVar6) == '\0') {
        if (cVar1 == '\x02') {
          *(short *)(param_1 + 0x4d) = (short)param_1[0x4d] + 1;
          piVar7 = g_pGlobalMapState;
        }
      }
      else {
        iVar10 = 0;
        do {
          sVar3 = (short)*(char *)(piVar7[3] + iVar6 + 0x11 + (int)(short)iVar10);
          if (sVar3 != -1) {
            psVar11 = (short *)((int)param_1 + sVar3 * 2 + 0x10e);
            cVar2 = (**(code **)(*piVar7 + 0xc4))(local_10,iVar10);
            *psVar11 = *psVar11 + (short)cVar2;
            piVar7 = g_pGlobalMapState;
          }
          iVar10 = iVar10 + 1;
        } while (iVar10 < 2);
        if ((*(char *)(piVar7[3] + 2 + iVar6) != '\0') && (cVar1 == '\x02')) {
          *(short *)(param_1 + 0x4d) = (short)param_1[0x4d] + 1;
          piVar7 = g_pGlobalMapState;
        }
        iVar10 = *(short *)(piVar7[3] + 0x14 + iVar6) * 0xa8;
        if (*(short *)(piVar7[4] + 4 + iVar10) == (short)local_10) {
          iVar10 = iVar10 + 0x82;
          iVar8 = 10;
          piVar5 = param_1 + 0x47;
          do {
            iVar10 = iVar10 + 2;
            *(short *)piVar5 = (short)*piVar5 + *(short *)(piVar7[4] + -2 + iVar10);
            iVar8 = iVar8 + -1;
            piVar5 = (int *)((int)piVar5 + 2);
            piVar7 = g_pGlobalMapState;
          } while (iVar8 != 0);
        }
      }
    }
    local_10 = local_10 + 1;
    local_c = local_c + 1;
    iVar6 = iVar6 + 0x24;
  } while ((short)local_10 < 0x1950);
  FreeHeapBufferIfNotNull(pcVar4);
  iVar6 = 0;
  psVar11 = (short *)((int)param_1 + 0x10e);
  do {
    if (*psVar11 < psVar11[0x17]) {
      (**(code **)(*param_1 + 0x114))(iVar6,*psVar11);
    }
    iVar6 = iVar6 + 1;
    psVar11 = psVar11 + 1;
  } while ((short)iVar6 < 0x17);
  return;
}

