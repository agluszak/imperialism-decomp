
int FUN_00562c00(short *param_1,short param_2)

{
  int iVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int local_14;
  int local_10;
  int local_8;
  short *local_4;
  
  local_14 = -1;
  local_10 = -1;
  iVar4 = 0;
  sVar7 = 0;
  local_8 = 0;
  iVar5 = 0;
  local_4 = param_1;
  do {
    iVar8 = local_14;
    iVar1 = local_10;
    if (*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + iVar4) == param_2) {
      iVar6 = *local_4 * 0xc;
      iVar8 = 0;
      do {
        sVar2 = thunk_StepHexTileIndexByDirectionWithWrapRules(local_8,iVar8);
        if ((sVar2 != -1) &&
           (*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + sVar2 * 0x24) ==
            *(char *)(iVar4 + 4 + *(int *)(g_pGlobalMapState + 0xc)))) {
          iVar6 = iVar6 + param_1[sVar2] * 2;
          if ((iVar8 == 4) || (iVar8 == 1)) {
            iVar6 = iVar6 + param_1[sVar2];
          }
        }
        iVar8 = iVar8 + 1;
      } while (iVar8 < 6);
      iVar8 = iVar5;
      iVar1 = iVar6;
      if ((local_14 == -1) || (local_10 < iVar6)) {
        sVar7 = 1;
      }
      else if (iVar6 == local_10) {
        sVar7 = sVar7 + 1;
        iVar3 = GenerateThreadLocalRandom15();
        if ((iVar3 % (int)sVar7 != 0) && (iVar8 = local_14, iVar1 = local_10, local_14 < 0xd8)) {
          iVar8 = iVar5;
          iVar1 = iVar6;
        }
      }
      else {
        iVar8 = local_14;
        iVar1 = local_10;
        if (local_14 < 0xd8) {
          iVar8 = iVar5;
          iVar1 = iVar6;
        }
      }
    }
    local_10 = iVar1;
    local_14 = iVar8;
    local_8 = local_8 + 1;
    iVar5 = iVar5 + 1;
    local_4 = local_4 + 1;
    iVar4 = iVar4 + 0x24;
  } while ((short)local_8 < 0x1878);
  return local_14;
}

