
void __fastcall FUN_004dd140(int param_1)

{
  short sVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  
  sVar2 = 0;
  iVar4 = 0;
  iVar3 = 0x5c;
  do {
    sVar1 = thunk_FUN_00550e70(iVar4);
    sVar2 = sVar2 + sVar1 * *(short *)(*(int *)(param_1 + 0x894) + iVar3);
    iVar3 = iVar3 + 2;
    iVar4 = iVar4 + 1;
  } while (iVar3 < 0x78);
  *(short *)(param_1 + 0xa4) = sVar2;
  *(short *)(param_1 + 0xa2) = sVar2;
  return;
}

