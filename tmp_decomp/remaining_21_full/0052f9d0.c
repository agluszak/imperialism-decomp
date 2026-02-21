// 0x0052f9d0 FUN_0052f9d0\n\n
void __fastcall FUN_0052f9d0(int param_1)

{
  short sVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  iVar2 = (int)*(short *)(*(int *)(param_1 + 4) + 0xc);
  iVar4 = g_pCityOrderCapabilityState + iVar2;
  local_18 = 0;
  local_14 = 1;
  local_10 = 2;
  local_c = 3;
  local_8 = 4;
  local_1c = (*(char *)(iVar4 + 0x27b + iVar2 * 0x1c) == '\x02') + 5;
  local_4 = 6;
  if (local_1c != 0) {
    puVar3 = &local_18;
    do {
      iVar2 = GenerateThreadLocalRandom15();
      iVar4 = CONCAT22((short)((uint)iVar4 >> 0x10),*(undefined2 *)puVar3);
      sVar1 = (**(code **)(g_pNationInteractionStateManager->vftable + 0x4c))(iVar4);
      if (iVar2 % 100 + 200 < (int)sVar1) {
        sVar1 = (**(code **)(**(int **)(param_1 + 4) + 0x78))(iVar4);
        if (sVar1 == 0) {
          (**(code **)(**(int **)(param_1 + 4) + 0x1a4))(iVar4,0);
        }
        else {
          sVar1 = (**(code **)(**(int **)(param_1 + 4) + 0x78))(iVar4);
          iVar2 = (int)sVar1 / 2;
          if (4 < iVar2) {
            iVar2 = 5;
          }
          (**(code **)(**(int **)(param_1 + 4) + 0x1a4))(iVar4,iVar2);
        }
      }
      puVar3 = puVar3 + 1;
      local_1c = local_1c + -1;
    } while (local_1c != 0);
  }
  iVar2 = GenerateThreadLocalRandom15();
  sVar1 = (**(code **)(g_pNationInteractionStateManager->vftable + 0x4c))(5);
  if (iVar2 % 100 + 200 < (int)sVar1) {
    sVar1 = (**(code **)(**(int **)(param_1 + 4) + 0x78))(5);
    if (sVar1 != 0) {
      sVar1 = (**(code **)(**(int **)(param_1 + 4) + 0x78))(5);
      iVar2 = (int)sVar1 / 2;
      if (4 < iVar2) {
        iVar2 = 5;
      }
      (**(code **)(**(int **)(param_1 + 4) + 0x1a4))(5,iVar2);
      return;
    }
    (**(code **)(**(int **)(param_1 + 4) + 0x1a4))(5,0);
  }
  return;
}

