// 0x0052fba0 FUN_0052fba0\n\n
void __thiscall
FUN_0052fba0(int param_1,undefined4 param_2,uint param_3,undefined4 param_4,undefined4 param_5)

{
  short *psVar1;
  ushort uVar2;
  undefined *puVar3;
  int iVar4;
  short sVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 unaff_EBX;
  undefined4 unaff_retaddr;
  
  sVar5 = (short)param_5;
  uVar7 = param_3;
  if (sVar5 == *(short *)(param_1 + 0x10)) {
    if ((short)*(ushort *)(param_1 + 0x12) < (short)param_3) {
      uVar7 = (uint)*(ushort *)(param_1 + 0x12);
    }
    sVar5 = (**(code **)(**(int **)(param_1 + 4) + 0x100))(param_5);
    if (sVar5 < (short)uVar7) {
      puVar3 = g_pNationInteractionStateManager->vftable;
      iVar4 = (*(int **)(param_1 + 4))[3];
      uVar6 = (**(code **)(**(int **)(param_1 + 4) + 0x100))(param_5,param_3,param_5,0,0);
      (**(code **)(puVar3 + 0x60))((short)iVar4,unaff_EBX,uVar6);
      return;
    }
  }
  else {
    uVar2 = *(ushort *)(param_1 + 0x1e + sVar5 * 2);
    psVar1 = (short *)(param_1 + 0x1e + sVar5 * 2);
    if ((short)uVar2 < 1) {
      uVar7 = 0;
    }
    else if ((short)uVar2 < (short)param_3) {
      uVar7 = (uint)uVar2;
    }
    sVar5 = (**(code **)(**(int **)(param_1 + 4) + 0x100))(param_5);
    if (sVar5 < (short)uVar7) {
      uVar7 = (**(code **)(**(int **)(param_1 + 4) + 0x100))(param_5);
    }
    *psVar1 = *psVar1 - (short)uVar7;
  }
  (**(code **)(g_pNationInteractionStateManager->vftable + 0x60))
            (CONCAT22((short)((uint)*(int *)(param_1 + 4) >> 0x10),
                      *(undefined2 *)(*(int *)(param_1 + 4) + 0xc)),unaff_retaddr,uVar7,param_3,
             param_5,0,0);
  return;
}

