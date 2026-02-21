
void FUN_00560e20(void)

{
  int iVar1;
  
  for (iVar1 = g_pMapActionContextListHead; iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x18)) {
    *(undefined2 *)(iVar1 + 0x44) = 0;
  }
  iVar1 = 0;
  do {
    iVar1 = iVar1 + 0xa8;
    *(undefined1 *)(*(int *)(g_pGlobalMapState + 0x10) + -8 + iVar1) = 0;
  } while (iVar1 < 0xfc00);
  return;
}

