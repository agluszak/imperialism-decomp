
int FUN_00562af0(short *param_1)

{
  short sVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  short *psVar5;
  int local_8;
  int local_4;
  
  iVar3 = 0;
  local_8 = 0;
  local_4 = 0;
  psVar5 = param_1;
  do {
    if (*psVar5 == 0) {
      iVar4 = 0;
      do {
        sVar2 = thunk_StepHexTileIndexByDirectionWithWrapRules(local_4,iVar4);
        sVar1 = *psVar5;
        if ((sVar1 == 0) &&
           ((sVar2 == -1 ||
            (*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + sVar2 * 0x24) !=
             *(char *)(iVar3 + 4 + *(int *)(g_pGlobalMapState + 0xc)))))) {
          *psVar5 = -1;
LAB_00562b72:
          local_8 = local_8 + 1;
        }
        else {
          sVar2 = param_1[sVar2];
          if ((0 < sVar2) && ((sVar1 == 0 || ((int)sVar2 < -(int)sVar1)))) {
            *psVar5 = -1 - sVar2;
            goto LAB_00562b72;
          }
        }
        iVar4 = iVar4 + 1;
      } while (iVar4 < 6);
    }
    iVar3 = iVar3 + 0x24;
    local_4 = local_4 + 1;
    psVar5 = psVar5 + 1;
    if (0x194f < (short)local_4) {
      iVar3 = 0x1950;
      do {
        if (*param_1 < 0) {
          *param_1 = -*param_1;
        }
        param_1 = param_1 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      return local_8;
    }
  } while( true );
}

