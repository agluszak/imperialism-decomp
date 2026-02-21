
/* Sets one grant entry at +0xE0 for target slot, updates cached treasury/cost aggregate (+0xAC),
   and notifies influence matrix/UI paths. Value bits are masked by 0x3FFF; 0xFFFF means clear
   entry. */

char __thiscall
SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int *param_1,short param_2,undefined4 param_3)

{
  ushort uVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  ushort uVar6;
  undefined4 *unaff_FS_OFFSET;
  char local_18;
  undefined4 uStack_c;
  undefined1 *puStack_8;
  int iStack_4;
  
  iStack_4 = 0xffffffff;
  puStack_8 = &LAB_00632288;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  iVar5 = (int)param_2;
  local_18 = '\x01';
  uVar1 = *(ushort *)((int)param_1 + iVar5 * 2 + 0xe0);
  uVar6 = (ushort)param_3;
  if (uVar6 != uVar1) {
    if (uVar6 != 0xffff) {
      cVar3 = (**(code **)(*param_1 + 0x1dc))();
      if (cVar3 == '\0') {
        local_18 = '\0';
        goto LAB_004de3ef;
      }
    }
    local_18 = '\x01';
    if (uVar1 != 0xffff) {
      param_1[0x2b] = param_1[0x2b] - (int)(short)(uVar1 & 0x3fff);
      (**(code **)(*param_1 + 0x38))();
    }
    if (uVar6 != 0xffff) {
      param_1[0x2b] = param_1[0x2b] + (int)(short)(uVar6 & 0x3fff);
      (**(code **)(*param_1 + 0x38))();
    }
    *(ushort *)((int)param_1 + iVar5 * 2 + 0xe0) = uVar6;
  }
LAB_004de3ef:
  if ((char)param_1[0x28] != '\0') {
    thunk_FUN_005033e0();
    if (((((char)param_1[0x28] != '\0') && (local_18 != '\0')) && (uVar6 != 0xffff)) &&
       (6 < param_2)) {
      bVar2 = false;
      iVar4 = 0;
      do {
        if (6 < iVar4) break;
        if ((iVar4 != (short)param_1[3]) &&
           (0xf9 < *(short *)(&g_pDiplomacyTurnStateManager->field_0x79c +
                             ((short)iVar4 * 0x17 + iVar5) * 2))) {
          bVar2 = true;
        }
        iVar4 = iVar4 + 1;
      } while (!bVar2);
      if (bVar2) {
        InitializeSharedStringRefFromEmpty();
        iStack_4 = 0;
        InitializeSharedStringRefFromEmpty();
        iStack_4._0_1_ = 1;
        (**(code **)(*g_pLocalizationTable + 0x84))();
        (**(code **)(*g_pLocalizationTable + 0x84))(0x2753);
        thunk_AssignStringSharedRefAndReturnThis();
        iStack_4._0_1_ = 2;
        thunk_AssignStringSharedRefAndReturnThis(&param_3);
        iStack_4._0_1_ = 1;
        thunk_DispatchLocalizedUiMessageWithTemplate(5);
        iStack_4 = (uint)iStack_4._1_3_ << 8;
        ReleaseSharedStringRefIfNotEmpty();
        iStack_4 = 0xffffffff;
        ReleaseSharedStringRefIfNotEmpty();
      }
    }
  }
  *unaff_FS_OFFSET = uStack_c;
  return local_18;
}

