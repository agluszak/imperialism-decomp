
void __fastcall FUN_00560470(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x10) + 1;
  *(int *)(param_1 + 0x10) = iVar1;
  if (*(int *)(param_1 + 8) <= iVar1) {
    iVar1 = *(int *)(param_1 + 0xc) + 1;
    *(undefined4 *)(param_1 + 0x10) = 0;
    *(int *)(param_1 + 0xc) = iVar1;
    if (5 < iVar1) {
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      *(undefined4 *)(param_1 + 0xc) = 0;
      thunk_StepHexRowColByDirectionWithWrapRules();
    }
  }
  thunk_StepHexRowColByDirectionWithWrapRules();
  return;
}

