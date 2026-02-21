
uint __fastcall FUN_00561490(int param_1)

{
  int iVar1;
  bool bVar2;
  void *pvVar3;
  uint uVar4;
  
  uVar4 = 0;
  for (pvVar3 = thunk_GetNavyPrimaryOrderListHead(); pvVar3 != (void *)0x0;
      pvVar3 = *(void **)((int)pvVar3 + 0x24)) {
    if (((*(int *)((int)pvVar3 + 8) == param_1) && (iVar1 = *(int *)((int)pvVar3 + 0xc), iVar1 != 0)
        ) && (*(char *)(iVar1 + 0x26) == '\0')) {
      if ((*(int *)(iVar1 + 8) == 3) || (*(int *)(iVar1 + 8) == 4)) {
        bVar2 = true;
      }
      else {
        bVar2 = false;
      }
      if (bVar2) {
        uVar4 = uVar4 | 1 << (*(byte *)((int)pvVar3 + 0x14) & 0x1f);
      }
    }
  }
  return uVar4;
}

