
void FUN_00563f50(void)

{
  int *piVar1;
  int iVar2;
  short sVar3;
  char cVar4;
  short sVar5;
  uint uVar6;
  undefined4 *puVar7;
  int *piVar8;
  int *pCurrentPortZone;
  int local_c;
  int local_8;
  int iStack_4;
  
  local_c = 0;
  local_8 = 0;
  do {
    cVar4 = *(char *)(*(int *)(g_pGlobalMapState + 0xc) + 0x16 + local_8);
    if ((cVar4 == '\x03') || (cVar4 == '\x0e')) {
      piVar8 = FindPortZoneByTile((short)local_c);
    }
    else {
      sVar5 = (short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + local_8 + 4);
      if (sVar5 < 0x17) {
        piVar8 = (int *)0x0;
      }
      else {
        piVar8 = (int *)(*(int *)(g_pActiveMapContextState + 8) + (sVar5 + -0x17) * 0x48);
      }
    }
    if (piVar8 != (int *)0x0) {
      cVar4 = (**(code **)(*piVar8 + 0x38))();
      if (cVar4 == '\0') {
        if (piVar8 != (int *)0x0) {
          iStack_4 = 0;
          do {
            sVar5 = thunk_StepHexTileIndexByDirectionWithWrapRules(local_c,iStack_4);
            if (sVar5 != -1) {
              sVar3 = *(short *)(*(int *)(g_pGlobalMapState + 0xc) + 0x14 + sVar5 * 0x24);
              iVar2 = *(int *)(g_pGlobalMapState + 0xc) + sVar5 * 0x24;
              if (sVar3 == -1) {
                pCurrentPortZone = (int *)0x0;
              }
              else {
                pCurrentPortZone = (int *)(*(int *)(g_pGlobalMapState + 0x10) + sVar3 * 0xa8);
              }
              if (pCurrentPortZone == (int *)0x0) {
                cVar4 = *(char *)(iVar2 + 0x16);
                if ((cVar4 == '\x03') || (cVar4 == '\x0e')) {
                  for (pCurrentPortZone = GetFirstPortZone(); pCurrentPortZone != (int *)0x0;
                      pCurrentPortZone = GetNextPortZone(pCurrentPortZone)) {
                    if ((((short)pCurrentPortZone[3] == sVar5) ||
                        ((short)pCurrentPortZone[8] == sVar5)) ||
                       ((short)pCurrentPortZone[0x12] == sVar5)) goto LAB_00564108;
                  }
                  pCurrentPortZone = (int *)0x0;
                }
                else {
                  sVar5 = (short)*(char *)(iVar2 + 4);
                  if (sVar5 < 0x17) {
                    pCurrentPortZone = (int *)0x0;
                  }
                  else {
                    pCurrentPortZone =
                         (int *)(*(int *)(g_pActiveMapContextState + 8) + (sVar5 + -0x17) * 0x48);
                  }
                }
LAB_00564108:
                if (((pCurrentPortZone == (int *)0x0) || (pCurrentPortZone == piVar8)) ||
                   (cVar4 = (**(code **)(*pCurrentPortZone + 0x38))(), cVar4 != '\0'))
                goto LAB_00564151;
                piVar1 = piVar8 + 9;
                uVar6 = 0;
                if (piVar8[0xc] != 0) {
                  puVar7 = (undefined4 *)piVar8[10];
                  do {
                    if ((int *)*puVar7 == pCurrentPortZone) {
                      puVar7 = (undefined4 *)piVar8[10] + uVar6;
                      goto joined_r0x0056414a;
                    }
                    uVar6 = uVar6 + 1;
                    puVar7 = puVar7 + 1;
                  } while (uVar6 < (uint)piVar8[0xc]);
                }
                puVar7 = (undefined4 *)0x0;
              }
              else {
                piVar1 = piVar8 + 0xd;
                uVar6 = 0;
                if (piVar8[0x10] != 0) {
                  puVar7 = (undefined4 *)piVar8[0xe];
                  do {
                    if ((int *)*puVar7 == pCurrentPortZone) {
                      puVar7 = (undefined4 *)piVar8[0xe] + uVar6;
                      goto joined_r0x0056414a;
                    }
                    uVar6 = uVar6 + 1;
                    puVar7 = puVar7 + 1;
                  } while (uVar6 < (uint)piVar8[0x10]);
                }
                puVar7 = (undefined4 *)0x0;
              }
joined_r0x0056414a:
              if (puVar7 == (undefined4 *)0x0) {
                (**(code **)*piVar1)(pCurrentPortZone);
              }
            }
LAB_00564151:
            iStack_4 = iStack_4 + 1;
          } while (iStack_4 < 6);
        }
      }
      else if (piVar8[0xc] == 0) {
        iVar2 = *(int *)(g_pActiveMapContextState + 8) +
                ((short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + (short)piVar8[3] * 0x24) +
                -0x17) * 0x48;
        (**(code **)piVar8[9])(iVar2);
        (*(code *)**(undefined4 **)(iVar2 + 0x24))(piVar8);
      }
    }
    local_c = local_c + 1;
    local_8 = local_8 + 0x24;
    if (0x194f < (short)local_c) {
      return;
    }
  } while( true );
}

