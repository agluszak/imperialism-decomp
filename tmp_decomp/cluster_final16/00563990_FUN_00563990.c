
undefined4 FUN_00563990(undefined4 param_1)

{
  char *pcVar1;
  short sVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int local_8;
  
  local_8 = 0;
  while( true ) {
    sVar2 = (short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 2 + (short)param_1 * 0x24);
    uVar3 = CONCAT22((short)((uint)((short)param_1 * 0x24) >> 0x10),sVar2);
    if (sVar2 == 0) break;
    if ((0x1a < sVar2) && (sVar2 < 0x2b)) {
      uVar3 = uVar3 - 0x10;
    }
    sVar2 = (short)uVar3;
    if ((sVar2 < 0xb) || (0x1a < sVar2)) {
      if ((0x2a < sVar2) && (sVar2 < 0x3b)) break;
    }
    else {
      uVar3 = (uint)*(ushort *)(&DAT_0065c632 + sVar2 * 2);
    }
    iVar8 = 0;
    sVar2 = *(short *)(&DAT_0065c668 + (local_8 + (short)uVar3 * 2) * 2);
    uVar4 = param_1;
    do {
      uVar4 = thunk_StepHexTileIndexByDirectionWithWrapRules(uVar4,sVar2);
      pcVar1 = (char *)(*(int *)(g_pGlobalMapState + 0xc) + (short)uVar4 * 0x24);
      if (*pcVar1 == '\x05') {
        return CONCAT22((short)((uint)pcVar1 >> 0x10),(short)uVar4);
      }
      sVar7 = (short)pcVar1[2];
      if (sVar7 == 0) break;
      if ((0x1a < sVar7) && (sVar7 < 0x2b)) {
        sVar7 = sVar7 + -0x10;
      }
      if ((sVar7 < 0xb) || (0x1a < sVar7)) {
        if ((0x2a < sVar7) && (sVar7 < 0x3b)) break;
      }
      else {
        sVar7 = *(short *)(&DAT_0065c632 + sVar7 * 2);
      }
      iVar5 = (int)sVar2;
      iVar6 = sVar7 * 4;
      sVar2 = *(short *)(&DAT_0065c668 + iVar6);
      sVar7 = (short)((iVar5 + 3) % 6);
      if (sVar2 == sVar7) {
        sVar2 = *(short *)(&DAT_0065c66a + iVar6);
      }
      else if (*(short *)(&DAT_0065c66a + iVar6) != sVar7) break;
      iVar8 = iVar8 + 1;
    } while (iVar8 < 100);
    local_8 = local_8 + 1;
    if (1 < local_8) {
      return CONCAT22((short)((uint)local_8 >> 0x10),0xffff);
    }
  }
  return CONCAT22((short)(uVar3 >> 0x10),0xffff);
}

