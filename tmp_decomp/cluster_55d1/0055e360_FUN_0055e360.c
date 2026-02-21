
int FUN_0055e360(short param_1,short param_2)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = (int)param_1 % 0x6c;
  uVar2 = (int)param_1 / 0x6c;
  if ((param_2 == 4) || ((2 < param_2 && ((uVar2 & 1) == 0)))) {
    iVar1 = iVar1 + -1;
    if ((short)iVar1 < 0) {
      if (*(char *)(g_pGlobalMapState + 0x20) != '\0') {
        return 0xffff;
      }
      iVar1 = 0x6b;
    }
  }
  else if (((param_2 == 1) || ((param_2 < 3 && ((uVar2 & 1) != 0)))) &&
          (iVar1 = iVar1 + 1, 0x6b < (short)iVar1)) {
    if (*(char *)(g_pGlobalMapState + 0x20) != '\0') {
      return 0xffff;
    }
    iVar1 = 0;
  }
  if ((param_2 == 5) || (param_2 == 0)) {
    uVar2 = uVar2 - 1;
    if ((short)uVar2 < 0) {
      return 0xffff;
    }
  }
  else if (((param_2 == 3) || (param_2 == 2)) && (uVar2 = uVar2 + 1, 0x3b < (short)uVar2)) {
    return 0xffff;
  }
  return iVar1 + uVar2 * 0x6c;
}

