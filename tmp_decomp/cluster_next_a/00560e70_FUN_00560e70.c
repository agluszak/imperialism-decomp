
int * __thiscall FUN_00560e70(int param_1,undefined4 param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  uint local_10;
  int local_c;
  int *local_4;
  
  local_c = -1;
  local_4 = (int *)0x0;
  local_10 = 0;
  if (*(int *)(param_1 + 0x30) != 0) {
    if (*(int *)(param_1 + 0x30) == 0) {
      piVar2 = (int *)0x0;
      goto LAB_00560ea8;
    }
    do {
      piVar2 = (int *)(*(int *)(param_1 + 0x28) + local_10 * 4);
LAB_00560ea8:
      piVar2 = (int *)*piVar2;
      iVar3 = *piVar2;
      cVar1 = (**(code **)(iVar3 + 0x38))();
      if ((cVar1 == '\0') || (cVar1 = (**(code **)(iVar3 + 0x40))(param_2), cVar1 != '\0')) {
        iVar3 = 0;
        iVar4 = 0;
        piVar5 = &g_pTerrainTypeDescriptorTable;
        do {
          if (((*piVar5 != 0) && (('\x01' << ((byte)iVar4 & 0x1f) & *(byte *)(piVar2 + 4)) != 0)) &&
             (cVar1 = (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x44))
                                (param_2,iVar4), cVar1 != '\0')) {
            iVar3 = iVar3 + 1;
          }
          piVar5 = piVar5 + 1;
          iVar4 = iVar4 + 1;
        } while ((int)piVar5 < 0x6a432c);
        if (local_c < iVar3) {
          local_c = iVar3;
          local_4 = piVar2;
        }
      }
      local_10 = local_10 + 1;
    } while (local_10 < *(uint *)(param_1 + 0x30));
  }
  return local_4;
}

