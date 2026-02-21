
/* Budget check used by diplomacy policy/grant paths: compares additional cost against (this+0x10 +
   this+0x8F0/100 - this+0xAC). */

undefined4 __thiscall CanAffordAdditionalDiplomacyCostAfterCommitments(int param_1,short param_2)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = *(int *)(param_1 + 0x10) + *(int *)(param_1 + 0x8f0) / 100;
  iVar2 = ((uVar1 & ((int)uVar1 < 1) - 1) - *(int *)(param_1 + 0xac)) - (int)param_2;
  return CONCAT31((int3)((uint)iVar2 >> 8),-1 < iVar2);
}

