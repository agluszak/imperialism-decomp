
undefined4 __thiscall FUN_00561dc0(int param_1,int param_2)

{
  char cVar1;
  short sVar2;
  
  if ((*(short *)(param_1 + 0x44) < 1) || (*(int *)(param_2 + 0x18) == param_1)) {
    return 0;
  }
  sVar2 = (short)*(char *)(*(int *)(g_pGlobalMapState + 0xc) + 4 + *(short *)(param_1 + 0x48) * 0x24
                          );
  if ((*(short *)(param_2 + 0x1c) != sVar2) &&
     (cVar1 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x48))
                        (CONCAT22((short)((uint)*(int *)(g_pGlobalMapState + 0xc) >> 0x10),sVar2),
                         *(short *)(param_2 + 0x1c)), cVar1 == '\0')) {
    return 0;
  }
  return 1;
}

