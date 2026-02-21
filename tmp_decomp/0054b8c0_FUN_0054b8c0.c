
undefined4 __thiscall FUN_0054b8c0(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  
  if (param_2 == -1) {
    sVar1 = thunk_GetActiveNationId();
    param_2 = (int)sVar1;
    if (param_2 == -1) {
      iVar2 = FUN_00405a3d();
      param_2 = 0;
      piVar3 = (int *)(g_pGameFlowState + 0x48);
      do {
        if (*piVar3 == iVar2) goto LAB_0054b905;
        param_2 = param_2 + 1;
        piVar3 = piVar3 + 1;
      } while (param_2 < 7);
      param_2 = -1;
    }
  }
LAB_0054b905:
  return *(undefined4 *)(param_1 + 0xbc + param_2 * 4);
}

