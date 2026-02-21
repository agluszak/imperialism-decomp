
int __fastcall FUN_005563d0(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 != 0) {
    iVar2 = 0;
    for (iVar1 = *(int *)(g_pNavyOrderManager + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x2c)) {
      if (param_1 == iVar1) {
        return iVar2;
      }
      if (*(short *)(iVar1 + 0x1c) == *(short *)(param_1 + 0x1c)) {
        iVar2 = iVar2 + 1;
      }
    }
  }
  return -1;
}

