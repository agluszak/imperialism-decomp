
void __thiscall FUN_0055c010(int param_1,int param_2,int *param_3,int *param_4)

{
  byte bVar1;
  bool bVar2;
  short sVar3;
  short sVar4;
  int *piVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int *piVar11;
  int local_c;
  int local_8;
  
  local_c = 0;
  local_8 = 0;
  do {
    if (2 < *param_3) break;
    if ((local_8 < 0xe) || (0x11 < local_8)) {
      local_c = local_c + 1;
      piVar5 = *(int **)(param_1 + 0xef0);
      if (local_c <= piVar5[2]) {
        do {
          piVar5 = (int *)(**(code **)(*piVar5 + 0x2c))(local_c);
          if ((*piVar5 == local_8) && (piVar5[1] == param_2)) goto LAB_0055c091;
          piVar5 = *(int **)(param_1 + 0xef0);
          local_c = local_c + 1;
        } while (local_c <= piVar5[2]);
      }
      piVar5 = (int *)0x0;
      local_c = 0;
LAB_0055c091:
      if (piVar5 == (int *)0x0) {
        local_c = 0;
        local_8 = local_8 + 1;
      }
      else {
        piVar11 = (int *)(param_1 + 0xc + ((param_2 * 3 + *param_4) * 3 + *param_3) * 0x3c);
        *(undefined1 *)(piVar11 + 0xe) = 0;
        iVar10 = piVar5[1];
        piVar11[4] = 1;
        *piVar11 = 1 << ((byte)iVar10 & 0x1f);
        piVar11[1] = piVar5[2];
        piVar11[5] = 1;
        piVar9 = piVar11 + 2;
        iVar10 = 2;
        do {
          *piVar9 = 0;
          piVar9[4] = 0;
          piVar9 = piVar9 + 1;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
        iVar10 = *piVar5;
        iVar8 = -iVar10 + -100;
        if ((iVar10 < 5) || (0x15 < iVar10)) {
          bVar2 = false;
        }
        else {
          bVar2 = true;
        }
        if (bVar2) {
          sVar3 = 0;
          iVar6 = 0;
          do {
            if ((piVar5[2] & 1 << ((byte)iVar6 & 0x1f)) != 0) {
              sVar3 = sVar3 + 1;
            }
            iVar6 = iVar6 + 1;
          } while (iVar6 < 0x17);
          if (1 < sVar3) {
            iVar8 = -iVar10 + -0x65;
          }
        }
        piVar5 = *(int **)(param_1 + 4);
        iVar10 = 0;
        if (0 < *(int *)(param_1 + 8)) {
          do {
            if (*piVar5 == iVar8) goto LAB_0055c14d;
            piVar5 = piVar5 + 6;
            iVar10 = iVar10 + 1;
          } while (iVar10 < *(int *)(param_1 + 8));
        }
        piVar5 = (int *)0x0;
LAB_0055c14d:
        if (piVar5 != (int *)0x0) {
          piVar9 = piVar11 + 8;
          for (iVar10 = 6; iVar10 != 0; iVar10 = iVar10 + -1) {
            *piVar9 = *piVar5;
            piVar5 = piVar5 + 1;
            piVar9 = piVar9 + 1;
          }
          iVar10 = *param_4;
          *param_4 = iVar10 + 1;
          if (iVar10 + 1 == 3) {
            *param_4 = 0;
            *param_3 = *param_3 + 1;
          }
        }
      }
    }
    else {
      local_8 = local_8 + 1;
    }
  } while (local_8 < 0x19);
  if (*param_3 < 3) {
    local_8 = 0x19;
    do {
      if (2 < *param_3) break;
      local_c = local_c + 1;
      piVar5 = *(int **)(param_1 + 0xef0);
      if (local_c <= piVar5[2]) {
        do {
          piVar5 = (int *)(**(code **)(*piVar5 + 0x2c))(local_c);
          if ((*piVar5 == local_8) && (piVar5[1] != param_2)) goto LAB_0055c203;
          piVar5 = *(int **)(param_1 + 0xef0);
          local_c = local_c + 1;
        } while (local_c <= piVar5[2]);
      }
      piVar5 = (int *)0x0;
      local_c = 0;
LAB_0055c203:
      if ((piVar5 == (int *)0x0) || (piVar5[2] == 1 << ((byte)param_2 & 0x1f))) {
        local_c = 0;
        local_8 = local_8 + 1;
      }
      else {
        piVar11 = (int *)(param_1 + 0xc + ((param_2 * 3 + *param_4) * 3 + *param_3) * 0x3c);
        *(undefined1 *)(piVar11 + 0xe) = 0;
        iVar10 = piVar5[1];
        piVar11[4] = 1;
        *piVar11 = 1 << ((byte)iVar10 & 0x1f);
        piVar11[1] = piVar5[2];
        piVar11[5] = 1;
        piVar9 = piVar11 + 2;
        iVar10 = 2;
        do {
          *piVar9 = 0;
          piVar9[4] = 0;
          piVar9 = piVar9 + 1;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
        piVar9 = *(int **)(param_1 + 4);
        iVar10 = 0;
        if (0 < *(int *)(param_1 + 8)) {
          do {
            if (*piVar9 == -100 - *piVar5) goto LAB_0055c290;
            piVar9 = piVar9 + 6;
            iVar10 = iVar10 + 1;
          } while (iVar10 < *(int *)(param_1 + 8));
        }
        piVar9 = (int *)0x0;
LAB_0055c290:
        if (piVar9 != (int *)0x0) {
          piVar5 = piVar11 + 8;
          for (iVar10 = 6; iVar10 != 0; iVar10 = iVar10 + -1) {
            *piVar5 = *piVar9;
            piVar9 = piVar9 + 1;
            piVar5 = piVar5 + 1;
          }
          iVar10 = *param_4;
          *param_4 = iVar10 + 1;
          if (iVar10 + 1 == 3) {
            *param_4 = 0;
            *param_3 = *param_3 + 1;
          }
        }
      }
    } while (local_8 < 0x1e);
    if (*param_3 < 3) {
      local_c = 0;
      do {
        piVar5 = *(int **)(param_1 + 0xef0);
        local_c = local_c + 1;
        if (local_c <= piVar5[2]) {
          do {
            piVar5 = (int *)(**(code **)(*piVar5 + 0x2c))(local_c);
            if ((*piVar5 == 0xf) && (piVar5[1] == param_2)) goto LAB_0055c332;
            piVar5 = *(int **)(param_1 + 0xef0);
            local_c = local_c + 1;
          } while (local_c <= piVar5[2]);
        }
        piVar5 = (int *)0x0;
        local_c = 0;
LAB_0055c332:
        if (piVar5 == (int *)0x0) goto LAB_0055c435;
        piVar11 = (int *)(param_1 + 0xc + ((param_2 * 3 + *param_4) * 3 + *param_3) * 0x3c);
        *(undefined1 *)(piVar11 + 0xe) = 0;
        *piVar11 = 1 << ((byte)piVar5[3] & 0x1f);
        iVar10 = 2;
        piVar11[4] = 2;
        piVar11[1] = piVar5[2];
        piVar11[5] = 1;
        piVar9 = piVar11 + 2;
        do {
          *piVar9 = 0;
          piVar9[4] = 0;
          piVar9 = piVar9 + 1;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
        iVar10 = -0x14;
        if ((*piVar5 < 5) || (0x15 < *piVar5)) {
          bVar2 = false;
        }
        else {
          bVar2 = true;
        }
        if (bVar2) {
          sVar3 = 0;
          iVar8 = 0;
          do {
            if ((piVar5[2] & 1 << ((byte)iVar8 & 0x1f)) != 0) {
              sVar3 = sVar3 + 1;
            }
            iVar8 = iVar8 + 1;
          } while (iVar8 < 0x17);
          if (1 < sVar3) {
            iVar10 = -0x15;
          }
        }
        piVar9 = *(int **)(param_1 + 4);
        iVar8 = 0;
        if (0 < *(int *)(param_1 + 8)) {
          do {
            if (*piVar9 == iVar10) goto LAB_0055c3fa;
            piVar9 = piVar9 + 6;
            iVar8 = iVar8 + 1;
          } while (iVar8 < *(int *)(param_1 + 8));
        }
        piVar9 = (int *)0x0;
LAB_0055c3fa:
        if (piVar9 != (int *)0x0) {
          piVar11 = piVar11 + 8;
          for (iVar10 = 6; iVar10 != 0; iVar10 = iVar10 + -1) {
            *piVar11 = *piVar9;
            piVar9 = piVar9 + 1;
            piVar11 = piVar11 + 1;
          }
          iVar10 = *param_4;
          *param_4 = iVar10 + 1;
          if (iVar10 + 1 == 3) {
            *param_4 = 0;
            *param_3 = *param_3 + 1;
          }
        }
        if ((piVar5 == (int *)0x0) || (2 < *param_3)) goto LAB_0055c435;
      } while( true );
    }
  }
  return;
LAB_0055c435:
  if (2 < *param_3) {
    return;
  }
  iVar10 = (*(int **)(g_pMapContextActionManager + 4))[2];
  if (0 < iVar10) {
    iVar8 = **(int **)(g_pMapContextActionManager + 4);
    iVar6 = GenerateThreadLocalRandom15();
    pbVar7 = (byte *)(**(code **)(iVar8 + 0x2c))(iVar6 % iVar10 + 1);
    iVar10 = *(int *)(pbVar7 + 4);
    piVar5 = (int *)(param_1 + 0xc + ((param_2 * 3 + *param_4) * 3 + *param_3) * 0x3c);
    if (((iVar10 == 0) || (iVar10 == 3)) || (iVar10 == 4)) {
      iVar10 = *(int *)(pbVar7 + 8);
      piVar5[4] = 3;
      *piVar5 = iVar10;
      iVar10 = (pbVar7[2] != 0) - 0x1a;
    }
    else {
      sVar3 = thunk_GetShortAtOffset14OrInvalid();
      *piVar5 = (int)sVar3;
      piVar5[4] = 4;
      iVar10 = -0x1b - (uint)(*(int *)(pbVar7 + 4) != 1);
    }
    *(undefined1 *)(piVar5 + 0xe) = 1;
    bVar1 = *pbVar7;
    piVar5[5] = 1;
    piVar5[1] = 1 << (bVar1 & 0x1f);
    bVar1 = pbVar7[1];
    piVar5[6] = 1;
    iVar8 = 0;
    piVar5[2] = 1 << (bVar1 & 0x1f);
    piVar5[3] = 0;
    piVar5[7] = 0;
    piVar9 = *(int **)(param_1 + 4);
    if (0 < *(int *)(param_1 + 8)) {
      do {
        if (*piVar9 == iVar10) goto LAB_0055c522;
        piVar9 = piVar9 + 6;
        iVar8 = iVar8 + 1;
      } while (iVar8 < *(int *)(param_1 + 8));
    }
    piVar9 = (int *)0x0;
LAB_0055c522:
    if (piVar9 != (int *)0x0) {
      piVar5 = piVar5 + 8;
      for (iVar10 = 6; iVar10 != 0; iVar10 = iVar10 + -1) {
        *piVar5 = *piVar9;
        piVar9 = piVar9 + 1;
        piVar5 = piVar5 + 1;
      }
      iVar10 = *param_4;
      *param_4 = iVar10 + 1;
      if (iVar10 + 1 == 3) {
        *param_4 = 0;
        sVar3 = 0;
        *param_3 = *param_3 + 1;
        goto LAB_0055c558;
      }
    }
  }
  sVar3 = 0;
LAB_0055c558:
  if (2 < *param_3) {
    return;
  }
  sVar4 = (short)param_2;
  if (sVar3 != 0) {
    sVar4 = 999;
  }
  local_c = 0;
  do {
    local_c = local_c + 1;
    piVar5 = *(int **)(param_1 + 0xef0);
    if (local_c <= piVar5[2]) {
      do {
        piVar5 = (int *)(**(code **)(*piVar5 + 0x2c))(local_c);
        if ((*piVar5 == 0x11) && (piVar5[1] == (int)sVar4)) goto LAB_0055c5c2;
        piVar5 = *(int **)(param_1 + 0xef0);
        local_c = local_c + 1;
      } while (local_c <= piVar5[2]);
    }
    piVar5 = (int *)0x0;
    local_c = 0;
LAB_0055c5c2:
    if (piVar5 == (int *)0x0) break;
    piVar9 = (int *)(param_1 + 0xc + ((param_2 * 3 + *param_4) * 3 + *param_3) * 0x3c);
    *(undefined1 *)(piVar9 + 0xe) = 0;
    iVar10 = piVar5[1];
    if (iVar10 == -1) {
      *piVar9 = 0;
      piVar9[4] = 0;
    }
    else {
      piVar9[4] = 1;
      *piVar9 = 1 << ((byte)iVar10 & 0x1f);
    }
    iVar10 = 3;
    piVar11 = piVar9;
    do {
      piVar11[1] = 0;
      piVar11[5] = 0;
      iVar10 = iVar10 + -1;
      piVar11 = piVar11 + 1;
    } while (iVar10 != 0);
    iVar10 = 0;
    piVar11 = *(int **)(param_1 + 4);
    if (0 < *(int *)(param_1 + 8)) {
      do {
        if (*piVar11 == -1000 - piVar5[2]) goto LAB_0055c652;
        piVar11 = piVar11 + 6;
        iVar10 = iVar10 + 1;
      } while (iVar10 < *(int *)(param_1 + 8));
    }
    piVar11 = (int *)0x0;
LAB_0055c652:
    if (piVar11 != (int *)0x0) {
      piVar9 = piVar9 + 8;
      for (iVar10 = 6; iVar10 != 0; iVar10 = iVar10 + -1) {
        *piVar9 = *piVar11;
        piVar11 = piVar11 + 1;
        piVar9 = piVar9 + 1;
      }
      iVar10 = *param_4;
      *param_4 = iVar10 + 1;
      if (iVar10 + 1 == 3) {
        *param_4 = 0;
        *param_3 = *param_3 + 1;
      }
    }
    if ((piVar5 == (int *)0x0) || (2 < *param_3)) break;
  } while( true );
  sVar3 = sVar3 + 1;
  if (1 < sVar3) {
    return;
  }
  goto LAB_0055c558;
}

