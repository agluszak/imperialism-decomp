
undefined4 __thiscall FUN_00560970(int param_1,int param_2)

{
  void *pvVar1;
  int iVar2;
  
  iVar2 = 0;
  for (pvVar1 = thunk_GetNavyPrimaryOrderListHead(); pvVar1 != (void *)0x0;
      pvVar1 = *(void **)((int)pvVar1 + 0x24)) {
    if ((*(int *)((int)pvVar1 + 8) == param_1) && (*(short *)((int)pvVar1 + 0x14) == param_2)) {
      iVar2 = thunk_FUN_00550670(pvVar1,0);
    }
  }
  if (iVar2 != 0) {
    return *(undefined4 *)(iVar2 + 0x20);
  }
  return 0;
}

