
undefined4 FUN_0055e550(byte *param_1,int *param_2,int param_3)

{
  int iVar1;
  
  if ((param_3 == 4) || ((2 < param_3 && ((*param_1 & 1) == 0)))) {
    iVar1 = *param_2;
    *param_2 = iVar1 + -1;
    if (iVar1 + -1 < 0) {
      if (*(char *)(g_pGlobalMapState + 0x20) != '\0') {
        return 0;
      }
      *param_2 = 0x6b;
    }
  }
  else if ((param_3 == 1) || ((param_3 < 3 && ((*param_1 & 1) != 0)))) {
    iVar1 = *param_2;
    *param_2 = iVar1 + 1;
    if (0x6b < iVar1 + 1) {
      if (*(char *)(g_pGlobalMapState + 0x20) != '\0') {
        return 0;
      }
      *param_2 = 0;
    }
  }
  if ((param_3 == 5) || (param_3 == 0)) {
    iVar1 = *(int *)param_1;
    *(int *)param_1 = iVar1 + -1;
    if (iVar1 + -1 < 0) {
      return 0;
    }
  }
  else if ((param_3 == 3) || (param_3 == 2)) {
    iVar1 = *(int *)param_1;
    *(int *)param_1 = iVar1 + 1;
    if (0x3b < iVar1 + 1) {
      return 0;
    }
  }
  return 1;
}

