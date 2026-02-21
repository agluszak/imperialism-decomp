
void FUN_0054dfc0(int param_1)

{
  int *piVar1;
  char cVar2;
  ushort uVar3;
  undefined4 *unaff_FS_OFFSET;
  char *pcStack_18;
  undefined1 auStack_14 [4];
  undefined1 *puStack_10;
  undefined4 local_c;
  undefined1 *puStack_8;
  int iStack_4;
  
  local_c = *unaff_FS_OFFSET;
  iStack_4 = 0xffffffff;
  puStack_8 = &LAB_00634ee8;
  *unaff_FS_OFFSET = &local_c;
  cVar2 = thunk_FUN_0054a9d0();
  if (cVar2 == '\0') {
    thunk_FUN_0054a410();
  }
  else {
    piVar1 = (int *)(&g_apNationStates)[param_1];
    if ((piVar1 != (int *)0x0) && ((char)piVar1[0x28] != '\0')) {
      cVar2 = (**(code **)(*piVar1 + 0xa0))();
      if (cVar2 != '\0') {
        uVar3 = GetAsyncKeyState(0x11);
        if ((uVar3 & 0x8000) == 0) {
          thunk_FUN_0054b0f0();
          *unaff_FS_OFFSET = local_c;
          return;
        }
        if (*(int *)((int)g_pLocalizationTable + 0x44) == 1) {
          InitializeSharedStringRefFromEmpty();
          iStack_4 = 0;
          InitializeSharedStringRefFromEmpty();
          iStack_4._0_1_ = 1;
          InitializeSharedStringRefFromEmpty();
          iStack_4 = CONCAT31(iStack_4._1_3_,2);
          FormatOverlayTerrainLabelText();
          thunk_LoadUiStringResourceByGroupAndIndex();
          scanBracketExpressions(g_pLocalizationTable,auStack_14,pcStack_18);
          puStack_10 = &stack0xffffffd4;
          thunk_AssignStringSharedRefAndReturnThis(auStack_14);
          cVar2 = thunk_DispatchLocalizedUiMessageWithTemplateA13A0();
          if (cVar2 != '\0') {
            thunk_FUN_0054a340();
            thunk_FUN_0054bd20();
          }
          iStack_4._0_1_ = 1;
          ReleaseSharedStringRefIfNotEmpty();
          iStack_4 = (uint)iStack_4._1_3_ << 8;
          ReleaseSharedStringRefIfNotEmpty();
          iStack_4 = 0xffffffff;
          ReleaseSharedStringRefIfNotEmpty();
          *unaff_FS_OFFSET = local_c;
          return;
        }
      }
    }
  }
  *unaff_FS_OFFSET = local_c;
  return;
}

