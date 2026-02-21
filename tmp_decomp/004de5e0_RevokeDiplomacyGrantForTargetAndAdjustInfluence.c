
void __thiscall RevokeDiplomacyGrantForTargetAndAdjustInfluence(int param_1,undefined4 param_2)

{
  ushort uVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = (int)(short)param_2;
  uVar1 = *(ushort *)(param_1 + 0xe0 + iVar3 * 2) & 0x3fff;
  if (uVar1 != 0) {
    uVar4 = (uint)(short)uVar1;
    (**(code **)(*(int *)(&g_pTerrainTypeDescriptorTable)[iVar3] + 0x38))(uVar4);
    *(int *)(param_1 + 0xac) = *(int *)(param_1 + 0xac) - uVar4;
    sVar2 = LookupOrderCompatibilityMatrixValue
                      (g_pDiplomacyTurnStateManager,(short)param_2,*(short *)(param_1 + 0xc));
    if (sVar2 == 2) {
      sVar2 = *(short *)(param_1 + 0xc);
      iVar3 = CONCAT22(sVar2 >> 0xf,
                       *(undefined2 *)
                        (&g_pDiplomacyTurnStateManager->field_0x79c + (sVar2 * 0x17 + iVar3) * 2));
      if (uVar4 < 0xbb9) {
        if (uVar4 == 3000) {
          (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x28))(sVar2,param_2,iVar3 + 4);
          return;
        }
        if (uVar4 == 1000) {
          (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x28))(sVar2,param_2,iVar3 + 2);
          return;
        }
      }
      else if (uVar4 == 5000) {
        iVar3 = iVar3 + 6;
      }
      else if (uVar4 == 10000) {
        (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x28))(sVar2,param_2,iVar3 + 10);
        return;
      }
      (**(code **)((int)g_pDiplomacyTurnStateManager->vftable + 0x28))(sVar2,param_2,iVar3);
    }
  }
  return;
}

