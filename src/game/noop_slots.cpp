// Manual no-op slot functions.
// Kept as plain C++ (no inline asm) for maintainable source-driven workflow.
//
// The originals are FPO (no frame pointer) even when they take callee-cleaned
// stack args, so force frame-pointer omission here; otherwise /Oy- wraps the
// `ret N` bodies in a push ebp/mov ebp,esp/pop ebp frame.
#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00412bf0
void NoOpTurnEventStateVtableSlot0C(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00412c10
void __stdcall NoOpTurnEventStateVtableSlot10(int unused) {
  (void)unused;
  return;
}

// FUNCTION: IMPERIALISM 0x0048a650
void HandleCityProductionNoOp(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0048a690
void HandleCityDialogNoOpA(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b5140
void ResetCityOrderItemDerivedStateNoop(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00500200
void NoOpTurnOrderNavigationVtableSlotA(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00500220
void NoOpTurnOrderNavigationVtableSlotB(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00572bb0
void UniversityDialogMethod_00405623(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005dbd10
void NoOpTurnEventStateVtableSlotFC(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e2b50
void NoOpJoinGameSelectionVtableSlotA(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e2b70
void NoOpJoinGameSelectionVtableSlotB(void) {
  return;
}

// --- Empty vtable-slot / callback no-ops (batch port). Each is a single
//     `ret` (or `ret N` for callee-cleaned stack args); modeled here as empty
//     bodies so MSVC emits the identical epilogue. ---

// FUNCTION: IMPERIALISM 0x00412bd0
void __stdcall TMacViewMgr_Slot02_NoOpRet4(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00426f80
void NoOpRuntimeCallback_00426f80(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00486300
void __stdcall NoOpTextPostLayoutHook(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00487f90
void __stdcall NoOpLinkedValueListHook20(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0048ab70
void __stdcall NoOpUiLifecycleHook(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004972e0
void NoOpQuickDrawLifecycleHookB(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00498ca0
void NoOpCallback_00498ca0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d6790
void __stdcall NoOpNationSelectedRegionAndMapCellLabelHook(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004da5c0
void NoOpNationPendingActionHook(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004dab00
void NoOpNationQueuedOrderHook(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005033e0
void __stdcall NoOpDiplomacyPolicyStateChangedHook(int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00503400
void __stdcall HandlePostPendingEventActivationNoOp(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0052efb0
void __stdcall NoOpForeignMinisterUtilityStub(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0052fd80
void NoOpForeignMinisterSlot24Handler(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0052fda0
void NoOpForeignMinisterSlot25Handler(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00531110
void NoOpForeignMinisterSlot32Handler(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00531af0
void NoOpTedForeignMinisterSlot25Handler(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534c40
void NoOpMissionVtableSlot30(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534ca0
void NoOpMissionVtableSlot3C(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534cf0
void NoOpMissionVtableSlot44(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534ed0
void __stdcall NoOpMissionVtableSlot84(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534ef0
void __stdcall NoOpMissionVtableSlot80Ret8(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534f10
void __stdcall NoOpMissionVtableSlot8CRet8(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534f30
void __stdcall NoOpMissionVtableSlot88Ret8(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534f50
void __stdcall NoOpMissionVtableSlot90Ret4(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541a00
void __stdcall NoOpDiplomacyTargetTransitionCallbackAlt(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541a20
void __stdcall NoOpGreatPowerCommandHandlerRet4(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0054c660
void __stdcall NoOpCallbackRet4(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0054c680
void __stdcall NoOpCallbackRet10(int, int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0054c6a0
void __stdcall NoOpCallbackRet18(int, int, int, int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0057c390
void NoOpVirtualStub_0057c390(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005d7190
void __stdcall NoOpTurnEventStateVtableSlotD4(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005dee80
void __stdcall NoOpRuntimeUiCallback_005dee80(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005df3f0
void __stdcall NoOpRuntimeUiCallback_005df3f0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005df410
void __stdcall NoOpRuntimeUiCallback_005df410(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005df780
void __stdcall NoOpRuntimeUiCallback_005df780(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e2490
void __stdcall NoOpRuntimeUiCallback_005e2490(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e3450
void NoOpInitializeGlobalTurnEventQueueManager(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e42a0
void __stdcall NoOpDialogModeTagChangedHook(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e50a0
void __stdcall NoOpAudioTickCallback_005e50a0(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e717b
void __stdcall NoOpRuntimeCallback_005e717b(int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e7370
void NoOpCrtThreadLifecycleHook(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00610c08
void __stdcall NoOpVirtualStub_00610c08(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0061180f
void NoOpVirtualStub_0061180f(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00618753
void __stdcall NoOpVirtualStub_00618753(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0061ec02
void NoOpVirtualStub_0061ec02(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00622a95
void NoOpThreadInitializationStub(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00624491
void NoOpPaddingStub_00624491(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x006244b7
void NoOpPaddingStub_006244b7(void) {
  return;
}
