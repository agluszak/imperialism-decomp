// 0x00532f70 FUN_00532f70\n\n
void __thiscall
FUN_00532f70(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  short sVar1;
  int iVar2;
  undefined4 unaff_retaddr;
  
  if (*(short *)(param_1 + 0x1e + (short)param_5 * 2) == 0) {
    sVar1 = (short)(*(int **)(param_1 + 4))[0x29];
    if (sVar1 < 0xc) {
      iVar2 = 1;
    }
    else {
      iVar2 = (0x18 < sVar1) + 2;
    }
    sVar1 = (**(code **)(**(int **)(param_1 + 4) + 0x100))(param_5);
    if (sVar1 < (short)iVar2) {
      iVar2 = (**(code **)(**(int **)(param_1 + 4) + 0x100))(param_5);
    }
    if ((short)param_2 <= (short)iVar2) {
      iVar2 = param_2;
    }
    (**(code **)(g_pNationInteractionStateManager->vftable + 0x60))
              (CONCAT22((short)((uint)*(int *)(param_1 + 4) >> 0x10),
                        *(undefined2 *)(*(int *)(param_1 + 4) + 0xc)),unaff_retaddr,iVar2,param_3,
               param_5,0,0);
    return;
  }
  thunk_FUN_0052fba0(param_2,param_3,param_4,param_5);
  return;
}

