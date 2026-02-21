
undefined1 FUN_00563b70(undefined4 param_1)

{
  char cVar1;
  short sVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  undefined1 local_d;
  int local_c;
  
  iVar8 = *(int *)(g_pGlobalMapState + 0xc);
  local_c = 0;
  cVar1 = *(char *)(iVar8 + 4 + (short)param_1 * 0x24);
  do {
    sVar2 = (short)*(char *)(iVar8 + 2 + (short)param_1 * 0x24);
    local_d = 0;
    if (sVar2 == 0) {
      return 0xff;
    }
    if ((0x1a < sVar2) && (sVar2 < 0x2b)) {
      sVar2 = sVar2 + -0x10;
    }
    if ((sVar2 < 0xb) || (0x1a < sVar2)) {
      if ((0x2a < sVar2) && (sVar2 < 0x3b)) {
        return 0xff;
      }
    }
    else {
      sVar2 = *(short *)(&DAT_0065c632 + sVar2 * 2);
    }
    iVar7 = 0;
    sVar2 = *(short *)(&DAT_0065c668 + (local_c + sVar2 * 2) * 2);
    uVar3 = param_1;
    do {
      uVar3 = thunk_StepHexTileIndexByDirectionWithWrapRules(uVar3,sVar2);
      sVar6 = (short)uVar3;
      if (sVar6 == -1) {
        return local_d;
      }
      iVar8 = *(int *)(g_pGlobalMapState + 0xc);
      iVar4 = iVar8 + sVar6 * 0x24;
      if (*(char *)(iVar8 + sVar6 * 0x24) == '\x05') {
        return local_d;
      }
      sVar6 = (short)*(char *)(iVar4 + 2);
      if (sVar6 == 0) break;
      if ((0x1a < sVar6) && (sVar6 < 0x2b)) {
        sVar6 = sVar6 + -0x10;
      }
      if ((sVar6 < 0xb) || (0x1a < sVar6)) {
        if ((0x2a < sVar6) && (sVar6 < 0x3b)) break;
      }
      else {
        sVar6 = *(short *)(&DAT_0065c632 + sVar6 * 2);
      }
      if (cVar1 != *(char *)(iVar4 + 4)) {
        if (0 < local_c) {
          return 1;
        }
        local_d = 1;
      }
      iVar4 = (int)sVar2;
      iVar5 = sVar6 * 4;
      sVar2 = *(short *)(&DAT_0065c668 + iVar5);
      sVar6 = (short)((iVar4 + 3) % 6);
      if (sVar2 == sVar6) {
        sVar2 = *(short *)(&DAT_0065c66a + iVar5);
      }
      else if (*(short *)(&DAT_0065c66a + iVar5) != sVar6) break;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 100);
    local_c = local_c + 1;
    if (1 < local_c) {
      return 0xff;
    }
  } while( true );
}

