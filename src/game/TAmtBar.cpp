// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

#pragma optimize("y", on)


// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

// FUNCTION: IMPERIALISM 0x005884c0
TradeAmountBarLayout* __cdecl CreateTAmtBarInstance(void) {
  TradeAmountBarLayout* amountBar =
      reinterpret_cast<TradeAmountBarLayout*>(AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
    amountBar->vftable = reinterpret_cast<void*>(kVtableTAmtBar);
    amountBar->rangeOrMaxValue = 0;
    amountBar->stepOrCurrentValue = 0;
    amountBar->auxValueA = 0;
    amountBar->auxValueB = 0;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00588560
void* __cdecl GetTAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTAmtBar);
}

// FUNCTION: IMPERIALISM 0x00588580
TradeAmountBarLayout* __fastcall ConstructTAmtBarBaseState(TradeAmountBarLayout* amountBar) {
  // ORIG_CALLCONV: __thiscall
  TradeScreenRuntimeBridge::ConstructUiResourceEntryBase(amountBar);
  amountBar->vftable = reinterpret_cast<void*>(kVtableTAmtBar);
  amountBar->rangeOrMaxValue = 0;
  amountBar->stepOrCurrentValue = 0;
  amountBar->auxValueA = 0;
  amountBar->auxValueB = 0;
  return amountBar;
}

void __fastcall thunk_DestructTViewBaseState_005885F0(TView* amountBar);

// FUNCTION: IMPERIALISM 0x005885c0
TradeAmountBarLayout* __fastcall DestructTAmtBarAndMaybeFree(TradeAmountBarLayout* amountBar,
                                                             int unusedEdx,
                                                             unsigned char freeSelfFlag) {
  // ORIG_CALLCONV: __thiscall
  (void)unusedEdx;
  thunk_DestructTViewBaseState_005885F0(reinterpret_cast<TView*>(amountBar));
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull((undefined4)amountBar);
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00401e65
void __fastcall thunk_DestructTViewBaseState_005885F0(TView* amountBar) {
  amountBar->~TView();
}

// FUNCTION: IMPERIALISM 0x00588610
void __stdcall WrapperFor_thunk_NoOpUiLifecycleHook_At00588610(int passthroughArg) {
  ((void(__cdecl*)(int))thunk_NoOpUiLifecycleHook)(passthroughArg);
}

// FUNCTION: IMPERIALISM 0x00588690
void TradeAmountBarLayout::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  // ORIG_CALLCONV: __thiscall
  QuickDrawSurfaceGuard surface;
  short barRange = rangeOrMaxValue;
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  TradeControl* control = reinterpret_cast<TradeControl*>(this);
  if (control->IsActionable() == 0 || control->Refresh() == 0) {
    return;
  }

  int contentBounds[4];
  control->QueryContentBounds(contentBounds);
  ApplyRectClipRegion(contentBounds);

  int frameBounds[4];
  control->QueryBounds(frameBounds);

  control->CtrlSlot78();

  short controlWidth = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x34);
  short controlHeight = *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x38);

  RECT panelRect;
  panelRect.left = frameBounds[0];
  panelRect.top = frameBounds[1];
  panelRect.right = frameBounds[0] + (int)controlWidth;
  panelRect.bottom = frameBounds[1] + (int)controlHeight;

  RECT contentRect;
  contentRect.left = contentBounds[0];
  contentRect.top = contentBounds[1];
  contentRect.right = contentBounds[2];
  contentRect.bottom = contentBounds[3];

  reinterpret_cast<void(__cdecl*)(void*, void*, RECT*, RECT*, int, int)>(
      BlitRectWithOptionalTransparency)(
      reinterpret_cast<void*>(ReadIntAt(kAddrPrimaryRenderSurfaceContext) + 4),
      reinterpret_cast<void*>(ReadIntAt(kAddrActiveQuickDrawSurfaceContext) + 4), &panelRect,
      &contentRect, 0, 0);

  short guideValue = 0;
  if (barRange > 0) {
    SetQuickDrawTextOrigin(0, 1);
    CallUiRuntimeSlot34(g_pUiRuntimeContext, auxValueB);
    SetQuickDrawStylePair(1, 7);
    guideValue = stepOrCurrentValue < barRange ? stepOrCurrentValue : barRange;
    DrawCenteredGuideLine((short)(guideValue - 1), 1);
    reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
  }

  short fillOrigin = guideValue > 0 ? (short)(guideValue + 1) : 0;
  SetQuickDrawTextOrigin(fillOrigin, 4);
  SetQuickDrawFillColor(0);
  SetQuickDrawStylePair(1, 1);
  DrawCenteredGuideLine(controlWidth, 4);
  SetQuickDrawTextOrigin(stepOrCurrentValue, 0);
  reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
  DrawCenteredGuideLine((short)(stepOrCurrentValue - 1), controlHeight);
  reinterpret_cast<void(__cdecl*)(int)>(SnapshotHitRegionToClipCache)(0);
}

// GHIDRA_NAME OrphanCallChain_C2_I15_00588630
// GHIDRA_PROTO undefined OrphanCallChain_C2_I15_00588630()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=2; instructions=15
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=2; instructions=15 */

// FUNCTION: IMPERIALISM 0x00588ff0
void TradeMovePanelContext::HandleTradeMoveStepCommand(int commandId, void* eventArg,
                                                       int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  void* owner = this;
  if (commandId == 100) {
    TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    int moveValue = moveControl->QueryValue();
    CallApplyMoveValueSlot1D0(owner, moveValue + 1);
    return;
  }
  if (commandId != 0x65) {
    ::HandleTradeMoveControlAdjustment(this, commandId, eventArg, eventExtra);
    return;
  }
  TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  int moveValue = moveControl->QueryValue();
  CallApplyMoveValueSlot1D0(owner, moveValue - 1);
}

// GHIDRA_NAME OrphanCallChain_C1_I06_005899c0
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_005899c0()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */
