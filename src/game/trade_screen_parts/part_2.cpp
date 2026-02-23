// Included by src/game/trade_screen.cpp.
// Contains trade-screen UI wrapper and panel functions (address-ordered).

// FUNCTION: IMPERIALISM 0x0058AAA0
IndustryAmtBarState *__cdecl CreateTShipAmtBarInstance(void)
{
  IndustryAmtBarState *amountBar = reinterpret_cast<IndustryAmtBarState *>(
      AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(&g_vtblTShipAmtBar);
    amountBar->cachedRangeAt60 = 0;
    amountBar->cachedRatioAt62 = 0;
    amountBar->cachedProductionAt64 = 0;
    amountBar->cachedStyleAt66 = 0;
  }
  return amountBar;
}









// FUNCTION: IMPERIALISM 0x0058AB40
void *__cdecl GetTShipAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTShipAmtBar);
}









// FUNCTION: IMPERIALISM 0x0058AB60
IndustryAmtBarState *IndustryAmtBarState::ConstructTShipAmtBarBaseState()
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(this);
  vftable = reinterpret_cast<void *>(&g_vtblTShipAmtBar);
  cachedRangeAt60 = 0;
  cachedRatioAt62 = 0;
  cachedProductionAt64 = 0;
  cachedStyleAt66 = 0;
  return this;
}









// FUNCTION: IMPERIALISM 0x0058ABA0
IndustryAmtBarState *
IndustryAmtBarState::DestructTShipAmtBarAndMaybeFree(unsigned char freeSelfFlag)
{
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)this);
  }
  return this;
}









// FUNCTION: IMPERIALISM 0x0058ABF0
void IndustryAmtBarState::SelectTradeSpecialCommodityAndRecomputeBarLimits(int passthroughArg)
{
  NationState *nationState =
      reinterpret_cast<NationState **>(kAddrGlobalNationStates)[QueryActiveNationId()];
  NationCityTradeState *cityState = nationState != 0 ? nationState->cityState : 0;
  selectedMetricRecord = cityState->specialCommodityRecordAt190;
  short productionCap =
      *(short *)(reinterpret_cast<char *>(cityState->scenarioTradeDescriptor) + 0x1c);
  cachedRatioAt62 = (short)barRangeRaw;
  cachedProductionAt64 = productionCap;
  cachedStyleAt66 = 0x3a;
  cachedRangeAt60 = (short)(0 / (int)productionCap);
  reinterpret_cast<void (__fastcall *)(IndustryAmtBarState *, int)>(::thunk_NoOpUiLifecycleHook)(
      this, passthroughArg);
}








// FUNCTION: IMPERIALISM 0x0058AE30
TradeAmountBarLayout *__cdecl CreateTTraderAmtBarInstance(void)
{
  TradeAmountBarLayout *amountBar = reinterpret_cast<TradeAmountBarLayout *>(
      AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void *>(&g_vtblTTraderAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}








// FUNCTION: IMPERIALISM 0x0058AED0
void *__cdecl GetTTraderAmtBarClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTTraderAmtBar);
}








// FUNCTION: IMPERIALISM 0x0058AEF0
TradeAmountBarLayout *__fastcall ConstructTTraderAmtBar_Vtbl00666ba0(TradeAmountBarLayout *amountBar)
{
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void *>(&g_vtblTTraderAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}








// FUNCTION: IMPERIALISM 0x0058AF30
void __fastcall DestructTTraderAmtBarMaybeFree(
    TradeAmountBarLayout *amountBar, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
}

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif







// FUNCTION: IMPERIALISM 0x0058B340
CivilianButtonState *__cdecl CreateTCivilianButtonInstance(void)
{
  CivilianButtonState *button = reinterpret_cast<CivilianButtonState *>(
      AllocateWithFallbackHandler(0xa0));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructUiClickablePictureResourceEntry(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTCivilianButton);
    button->buttonTag = 0xc;
  }
  return button;
}







// FUNCTION: IMPERIALISM 0x0058B3C0
void *__cdecl GetTCivilianButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTCivilianButton);
}







// FUNCTION: IMPERIALISM 0x0058B3E0
CivilianButtonState *__fastcall ConstructTCivilianButtonBaseState(CivilianButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructUiClickablePictureResourceEntry(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTCivilianButton);
  button->buttonTag = 0xc;
  return button;
}







// FUNCTION: IMPERIALISM 0x0058B410
CivilianButtonState *__fastcall DestructTCivilianButtonAndMaybeFree(
    CivilianButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(button);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}







// FUNCTION: IMPERIALISM 0x0058B5C0
HQButtonState *__cdecl CreateTHQButtonInstance(void)
{
  HQButtonState *button = reinterpret_cast<HQButtonState *>(AllocateWithFallbackHandler(0x9c));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTHQButton);
  }
  return button;
}







// FUNCTION: IMPERIALISM 0x0058B640
void *__cdecl GetTHQButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTHQButton);
}







// FUNCTION: IMPERIALISM 0x0058B660
HQButtonState *__fastcall ConstructTHQButtonBaseState(HQButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTHQButton);
  return button;
}







// FUNCTION: IMPERIALISM 0x0058B690
HQButtonState *__fastcall DestructTHQButtonAndMaybeFree(
    HQButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(button);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}






// FUNCTION: IMPERIALISM 0x0058B6E0
void __fastcall WrapperFor_thunk_NoOpUiLifecycleHook_At0058b6e0(HQButtonState *button)
{
  short glyph = button->glyphBase84;
  thunk_NoOpUiLifecycleHook();
  button->glyph98 = 0;
  button->glyph90 = glyph;
  button->buttonTag = 0xc;
  button->glyph92 = (short)(glyph + 1);
  button->glyph94 = (short)(glyph + 2);
  button->glyph96 = (short)(glyph + 3);
}






// FUNCTION: IMPERIALISM 0x0058B7F0
void __fastcall WrapperFor_HandleCityDialogToggleCommandOrForward_At0058b7f0(
    HQButtonState *button, int unusedEdx, int commandId)
{
  (void)unusedEdx;
  TradeControl *control = reinterpret_cast<TradeControl *>(button);
  if (commandId == 0xc) {
    if (button->toggleStateAt64 == 0) {
      control->InvokeSlot1CC(1, 1);
    }
    thunk_HandleCityDialogToggleCommandOrForward();
    return;
  }
  if (commandId != 0x1f) {
    if (commandId != 0x20) {
      thunk_HandleCityDialogToggleCommandOrForward();
      return;
    }
    control->InvokeSlot1CC(0, 1);
    return;
  }
  control->InvokeSlot1CC(1, 1);
}







// FUNCTION: IMPERIALISM 0x0058B960
PlacardState *__cdecl CreateTPlacardInstance(void)
{
  PlacardState *placard = reinterpret_cast<PlacardState *>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void *>(&g_vtblTPlacard);
    placard->placardValue = 0;
  }
  return placard;
}







// FUNCTION: IMPERIALISM 0x0058B9F0
void *__cdecl GetTPlacardClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTPlacard);
}







// FUNCTION: IMPERIALISM 0x0058BA10
PlacardState *__fastcall ConstructTPlacardBaseState(PlacardState *placard)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void *>(&g_vtblTPlacard);
  placard->placardValue = 0;
  return placard;
}







// FUNCTION: IMPERIALISM 0x0058BA40
PlacardState *__fastcall DestructTPlacardAndMaybeFree(
    PlacardState *placard, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(placard);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)placard);
  }
  return placard;
}







// FUNCTION: IMPERIALISM 0x0058BE30
PlacardState *__cdecl CreateTArmyPlacardInstance(void)
{
  PlacardState *placard = reinterpret_cast<PlacardState *>(AllocateWithFallbackHandler(0x94));
  if (placard != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
    placard->vftable = reinterpret_cast<void *>(&g_vtblTArmyPlacard);
    placard->placardValue = (short)0xffff;
  }
  return placard;
}







// FUNCTION: IMPERIALISM 0x0058BEB0
void *__cdecl GetTArmyPlacardClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTArmyPlacard);
}







// FUNCTION: IMPERIALISM 0x0058BED0
PlacardState *__fastcall ConstructTArmyPlacardBaseState(PlacardState *placard)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(placard);
  placard->vftable = reinterpret_cast<void *>(&g_vtblTArmyPlacard);
  placard->placardValue = (short)0xffff;
  return placard;
}







// FUNCTION: IMPERIALISM 0x0058BF00
PlacardState *__fastcall DestructTArmyPlacardAndMaybeFree(
    PlacardState *placard, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(placard);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)placard);
  }
  return placard;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif






// FUNCTION: IMPERIALISM 0x0058BF50
void __fastcall WrapperFor_GetActiveNationId_At0058bf50(
    PlacardState *placard, int unusedEdx, short requestedValue)
{
  (void)unusedEdx;
  short nationId = (short)QueryActiveNationId();
  int controlIndex = *reinterpret_cast<int *>(reinterpret_cast<char *>(placard) + 0x1c);
  char *cityOrderBase = *reinterpret_cast<char **>(kAddrCityOrderCapabilityState);
  short baseSprite = *reinterpret_cast<short *>(
      cityOrderBase + 0x1f2d3b76 + (controlIndex + (int)nationId * 10) * 2);

  if (requestedValue != placard->placardValue) {
    short sprite = (short)(baseSprite + 0x4c4);
    if (requestedValue < 1) {
      sprite = (short)(baseSprite + 0x4e2);
    }
    reinterpret_cast<TradeControl *>(placard)->SetBitmap((int)sprite, 1);
    reinterpret_cast<TradeControl *>(placard)->InvokeSlotE4();
  }
  placard->placardValue = requestedValue;
}






// FUNCTION: IMPERIALISM 0x0058C140
void __fastcall HandlePlusMinusCommandAndInvokeVslot1CC(
    PlacardState *placard, int unusedEdx, int *arg1, int *arg2)
{
  (void)unusedEdx;
  (void)arg1;
  TradeControl *control = reinterpret_cast<TradeControl *>(placard);
  if (arg2[7] == kControlTagPlus) {
    int updatedValue = (int)ActivateFirstActiveTacticalUnitByCategoryAtTile();
    control->InvokeSlot1CC(updatedValue, 1);
    return;
  }
  if (arg2[7] == kControlTagMinu) {
    int updatedValue = (int)ActivateFirstIdleTacticalUnitByCategoryAtTile();
    control->InvokeSlot1CC(updatedValue, 1);
  }
}





// FUNCTION: IMPERIALISM 0x0058C1E0
NumberedArrowButtonState *__cdecl CreateTNumberedArrowButtonInstance(void)
{
  NumberedArrowButtonState *button = reinterpret_cast<NumberedArrowButtonState *>(
      AllocateWithFallbackHandler(0x88));
  if (button != 0) {
    TradeScreenRuntimeBridge::ConstructUiCommandTagResourceEntryBase(button);
    button->vftable = reinterpret_cast<void *>(&g_vtblTNumberedArrowButton);
    button->value84 = 0;
    button->value86 = 0;
  }
  return button;
}





// FUNCTION: IMPERIALISM 0x0058C280
void *__cdecl GetTNumberedArrowButtonClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTNumberedArrowButton);
}





// FUNCTION: IMPERIALISM 0x0058C2A0
NumberedArrowButtonState *__fastcall
ConstructTNumberedArrowButtonBaseState(NumberedArrowButtonState *button)
{
  TradeScreenRuntimeBridge::ConstructUiCommandTagResourceEntryBase(button);
  button->vftable = reinterpret_cast<void *>(&g_vtblTNumberedArrowButton);
  button->value84 = 0;
  button->value86 = 0;
  return button;
}





// FUNCTION: IMPERIALISM 0x0058C2E0
NumberedArrowButtonState *__fastcall DestructTNumberedArrowButtonAndMaybeFree(
    NumberedArrowButtonState *button, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  thunk_DestructEngineerDialogBaseState();
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)button);
  }
  return button;
}




// FUNCTION: IMPERIALISM 0x0058C330
void __fastcall OrphanCallChain_C1_I08_0058c330(
    NumberedArrowButtonState *button, int unusedEdx, short value84, char refreshFlag)
{
  (void)unusedEdx;
  button->value84 = value84;
  if (refreshFlag != '\0') {
    reinterpret_cast<TradeControl *>(button)->InvokeSlotE4();
  }
}




// FUNCTION: IMPERIALISM 0x0058C360
void __fastcall OrphanCallChain_C2_I23_0058c360(
    NumberedArrowButtonState *button, int unusedEdx, short value86, char refreshFlag)
{
  (void)unusedEdx;
  int bounds[4];
  if (button->value86 != value86) {
    if (refreshFlag != '\0') {
      reinterpret_cast<TradeControl *>(button)->InvokeSlotE4();
      reinterpret_cast<TradeControl *>(button)->QueryBounds(bounds);
    }
    button->value86 = value86;
  }
}




// FUNCTION: IMPERIALISM 0x0058C7C0
void __fastcall WrapperFor_thunk_HandleCursorHoverSelectionByChildHitTestAndFallback_At0058c7c0(
    NumberedArrowButtonState *button, int unusedEdx, int *cursorPoint, int hitArg)
{
  (void)unusedEdx;
  TradeControl *control = reinterpret_cast<TradeControl *>(button);
  if (control->IsActionable() != '\0') {
    if (cursorPoint[1] < button->width38 / 2) {
      button->hoverTag4e = 0x100;
      reinterpret_cast<void (__fastcall *)(NumberedArrowButtonState *, int *, int)>(
          ::thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(button, cursorPoint, hitArg);
      return;
    }
    button->hoverTag4e = (short)0xffff;
  }
  reinterpret_cast<void (__fastcall *)(NumberedArrowButtonState *, int *, int)>(
      ::thunk_HandleCursorHoverSelectionByChildHitTestAndFallback)(button, cursorPoint, hitArg);
}





// FUNCTION: IMPERIALISM 0x0058C830
CombatReportViewState *__cdecl CreateTCombatReportViewInstance(void)
{
  CombatReportViewState *view = reinterpret_cast<CombatReportViewState *>(
      AllocateWithFallbackHandler(0xa0));
  if (view != 0) {
    TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
    view->vftable = reinterpret_cast<void *>(&g_vtblTCombatReportView);
  }
  return view;
}





// FUNCTION: IMPERIALISM 0x0058C8B0
void *__cdecl GetTCombatReportViewClassNamePointer(void)
{
  return reinterpret_cast<void *>(&g_pClassDescTCombatReportView);
}





// FUNCTION: IMPERIALISM 0x0058C8D0
CombatReportViewState *__fastcall ConstructTCombatReportViewBaseState(CombatReportViewState *view)
{
  TradeScreenRuntimeBridge::ConstructPictureResourceEntryBase(view);
  view->vftable = reinterpret_cast<void *>(&g_vtblTCombatReportView);
  return view;
}





// FUNCTION: IMPERIALISM 0x0058C900
CombatReportViewState *__fastcall DestructTCombatReportViewAndMaybeFree(
    CombatReportViewState *view, int unusedEdx, unsigned char freeSelfFlag)
{
  (void)unusedEdx;
  TradeScreenRuntimeBridge::DestructCityDialogSharedBaseState(view);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)view);
  }
  return view;
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
