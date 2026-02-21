
void __fastcall FUN_0055fef0(int param_1)

{
  short sVar1;
  short sVar2;
  int iVar3;
  short sVar4;
  short sVar5;
  
  sVar1 = *(short *)(param_1 + 0xc);
  sVar4 = 1;
  sVar5 = 1;
  do {
    iVar3 = *(int *)(g_pGlobalMapState + 0xc) + sVar1 * 0x24;
    if (*(char *)(iVar3 + 0x16) == -1) {
      sVar2 = (short)*(char *)(iVar3 + 4);
      if (sVar2 < 0x17) {
        iVar3 = 0;
      }
      else {
        iVar3 = *(int *)(g_pActiveMapContextState + 8) + (sVar2 + -0x17) * 0x48;
      }
      if (iVar3 != 0) {
        return;
      }
    }
    sVar1 = sVar1 + sVar5 * sVar4;
    sVar5 = sVar5 + 1;
    sVar4 = -sVar4;
  } while( true );
}

