
/* WARNING: Removing unreachable block (ram,0x004de710) */
/* Affordability check for replacing target grant entry: compares current grant value (0x3FFF mask)
   vs proposed value against available budget derived from (this+0x8F0)/100 + (this+0x10). */

bool __thiscall CanAffordDiplomacyGrantEntryForTarget(int param_1,short param_2,ushort param_3)

{
  uint uVar1;
  ushort uVar2;
  ushort uVar3;
  
  uVar3 = 0;
  uVar2 = *(ushort *)(param_1 + 0xe0 + param_2 * 2);
  if (0 < (short)uVar2) {
    uVar3 = uVar2 & 0x3fff;
  }
  uVar1 = *(int *)(param_1 + 0x8f0) / 100 + *(int *)(param_1 + 0x10);
  return -1 < (int)(((int)(short)uVar3 - (int)(short)(param_3 & 0x3fff)) +
                   (uVar1 & ((int)uVar1 < 1) - 1));
}

