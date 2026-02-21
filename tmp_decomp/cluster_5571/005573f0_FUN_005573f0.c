
undefined4 * FUN_005573f0(undefined2 param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_c;
  undefined1 *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0063538d;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  puVar2 = (undefined4 *)AllocateWithFallbackHandler(0x1c);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    *puVar2 = &g_vtblRefCountedObjectBase;
    local_4._0_1_ = 1;
    local_4._1_3_ = 0;
    *(undefined2 *)(puVar2 + 1) = param_1;
    puVar2[2] = 0;
    InitializeSharedStringRefFromEmpty();
    *(undefined2 *)(puVar2 + 4) = 0;
    puVar2[5] = g_pNavySecondaryOrderList;
    puVar2[6] = 0;
    *puVar2 = &PTR_LAB_0065c498;
    local_4 = CONCAT31(local_4._1_3_,2);
    g_pNavySecondaryOrderList = puVar2;
    if (puVar2[5] != 0) {
      *(undefined4 **)(puVar2[5] + 0x18) = puVar2;
    }
    if (*(short *)(puVar2 + 1) != -1) {
      thunk_GenerateMappedFlavorTextByNationSlotField0C(puVar2 + 3);
      for (puVar1 = g_pNavySecondaryOrderList; puVar1 != (undefined4 *)0x0;
          puVar1 = (undefined4 *)puVar1[5]) {
        if ((puVar1 != puVar2) &&
           (iVar3 = CompareAnsiStringsWithMbcsAwareness(puVar1[3],puVar2[3]), iVar3 == 0)) {
          thunk_RemoveDuplicateNavySecondaryOrdersByDisplayName();
        }
      }
    }
  }
  local_4 = 0xffffffff;
  if (puVar2 == (undefined4 *)0x0) {
                    /* WARNING: Subroutine does not return */
    MessageBoxA((HWND)0x0,s_Nil_Pointer_00694fc8,s_Failure_00694fd8,0x30);
  }
  *unaff_FS_OFFSET = local_c;
  return puVar2;
}

