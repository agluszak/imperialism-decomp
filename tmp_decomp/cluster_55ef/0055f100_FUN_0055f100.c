
/* WARNING: Removing unreachable block (ram,0x0055f119) */

int FUN_0055f100(short param_1)

{
  int iVar1;
  
  iVar1 = g_pMapActionContextListHead;
  if (param_1 == -1) {
    return 0;
  }
  for (; (iVar1 != 0 && (*(short *)(iVar1 + 0x14) != param_1)); iVar1 = *(int *)(iVar1 + 0x18)) {
  }
  return iVar1;
}

