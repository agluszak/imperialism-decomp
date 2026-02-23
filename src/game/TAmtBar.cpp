// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

// FUNCTION: IMPERIALISM 0x00588610
void __stdcall WrapperFor_thunk_NoOpUiLifecycleHook_At00588610(int passthroughArg) {
  ((void(__cdecl*)(int))thunk_NoOpUiLifecycleHook)(passthroughArg);
}

// GHIDRA_NAME OrphanCallChain_C2_I15_00588630
// GHIDRA_PROTO undefined OrphanCallChain_C2_I15_00588630()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=2; instructions=15
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=2; instructions=15 */

// FUNCTION: IMPERIALISM 0x00588FF0
void TradeMovePanelContext::HandleTradeMoveStepCommand(int commandId) {
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
    HandleTradeMoveControlAdjustment();
    return;
  }

  TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  int moveValue = moveControl->QueryValue();
  if (commandId == 0x65) {
    CallApplyMoveValueSlot1D0(owner, moveValue - 1);
  }
}

// GHIDRA_NAME OrphanCallChain_C1_I06_005899c0
// GHIDRA_PROTO undefined OrphanCallChain_C1_I06_005899c0()
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT [OrphanCallChain] no incoming code refs; calls=1; instructions=6
// GHIDRA_COMMENT_END
/* [OrphanCallChain] no incoming code refs; calls=1; instructions=6 */
