
undefined4 __fastcall FUN_0054a9d0(int param_1)

{
  short sVar1;
  
  if (*(int *)(param_1 + 0xd8) == 0x676f696e) {
    sVar1 = thunk_GetActiveNationId();
    if (sVar1 != -1) {
      return 1;
    }
  }
  return 0;
}

