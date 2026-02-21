
void __fastcall FUN_00552450(int param_1)

{
  int iVar1;
  int iVar2;
  
  thunk_GenerateMappedFlavorTextByNationSlotField0C((undefined4 *)(param_1 + 0xc));
  for (iVar1 = g_pNavySecondaryOrderList; iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x14)) {
    if ((iVar1 != param_1) &&
       (iVar2 = CompareAnsiStringsWithMbcsAwareness
                          (*(undefined4 *)(iVar1 + 0xc),*(undefined4 *)(param_1 + 0xc)), iVar2 == 0)
       ) {
      thunk_FUN_00552450();
    }
  }
  return;
}

