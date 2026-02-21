
short __thiscall FUN_00560150(void *param_1,int param_2)

{
  char *pcVar1;
  bool bVar2;
  short sVar3;
  void *pvVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int local_c;
  int local_8;
  int local_4;
  
  uVar7 = 0;
  iVar5 = g_pGlobalMapState;
  do {
    pcVar1 = (char *)(*(int *)(iVar5 + 0xc) + (short)uVar7 * 0x24);
    if (*pcVar1 == '\x05') {
      if ((pcVar1[0x16] == '\x03') || (pcVar1[0x16] == '\x0e')) {
        pvVar4 = FindPortZoneByTile((short)uVar7);
        iVar5 = g_pGlobalMapState;
      }
      else if (pcVar1[4] < 0x17) {
        pvVar4 = (void *)0x0;
      }
      else {
        pvVar4 = (void *)(*(int *)(g_pActiveMapContextState + 8) + ((short)pcVar1[4] + -0x17) * 0x48
                         );
      }
      if (pvVar4 == param_1) {
        iVar8 = 0;
        do {
          sVar3 = thunk_StepHexTileIndexByDirectionWithWrapRules(uVar7,iVar8);
          if ((sVar3 != -1) &&
             (pcVar1 = (char *)(*(int *)(g_pGlobalMapState + 0xc) + sVar3 * 0x24), *pcVar1 != '\x05'
             )) {
            sVar3 = *(short *)(pcVar1 + 0x14);
            if (sVar3 == -1) {
              iVar5 = 0;
            }
            else {
              iVar5 = *(int *)(g_pGlobalMapState + 0x10) + sVar3 * 0xa8;
            }
            if (iVar5 == param_2) break;
          }
          iVar8 = iVar8 + 1;
        } while (iVar8 < 6);
        iVar5 = g_pGlobalMapState;
        if (iVar8 < 6) break;
      }
    }
    uVar7 = uVar7 + 1;
  } while ((short)uVar7 < 0x1950);
  if (0x194f < (short)uVar7) {
    uVar7 = (uint)(ushort)(*(short *)((int)param_1 + 0xc) + 0x6c);
  }
  sVar3 = (short)uVar7;
  iVar9 = (int)sVar3;
  iVar8 = thunk_FUN_0055ff70(iVar9,param_1,param_2);
  iVar5 = iVar9 / 0x6c;
  iVar9 = iVar9 % 0x6c;
  local_c = 0;
  local_8 = 5;
  local_4 = 1;
  thunk_AdvanceSpiralSearchStateAndStepHexCoordinates(0);
  bVar2 = true;
  while (bVar2) {
    if ((((iVar5 < 0) || (0x3b < iVar5)) || (iVar9 < 0)) || (0x6b < iVar9)) {
      sVar3 = -1;
    }
    else {
      sVar3 = (short)iVar9 + (short)iVar5 * 0x6c;
    }
    if ((sVar3 < 0) || (0x194f < sVar3)) {
      bVar2 = false;
    }
    else {
      bVar2 = true;
    }
    if (bVar2) {
      if (((iVar5 < 0) || (0x3b < iVar5)) || ((iVar9 < 0 || (0x6b < iVar9)))) {
        iVar6 = -1;
      }
      else {
        iVar6 = iVar9 + iVar5 * 0x6c;
      }
      iVar6 = thunk_FUN_0055ff70(iVar6,param_1,param_2);
      if (iVar8 < iVar6) {
        iVar8 = iVar6;
        if ((((iVar5 < 0) || (0x3b < iVar5)) || (iVar9 < 0)) || (0x6b < iVar9)) {
          uVar7 = 0xffffffff;
        }
        else {
          uVar7 = iVar9 + iVar5 * 0x6c;
        }
      }
    }
    sVar3 = (short)uVar7;
    local_4 = local_4 + 1;
    if (local_c <= local_4) {
      local_4 = 0;
      local_8 = local_8 + 1;
      if (5 < local_8) {
        local_c = local_c + 1;
        local_8 = 0;
        thunk_StepHexRowColByDirectionWithWrapRules();
      }
    }
    thunk_StepHexRowColByDirectionWithWrapRules();
    bVar2 = local_c < 0xc;
  }
  return sVar3;
}

