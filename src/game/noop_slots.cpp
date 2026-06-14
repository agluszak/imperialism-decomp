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

// --- Trivial empty stubs (Stub/Return/Dummy-named free functions whose original
//     is a bare `ret` or callee-cleaned `ret N`). Batch port; FPO pragma above
//     keeps the `ret N` epilogues frameless. ---

// FUNCTION: IMPERIALISM 0x004136c0
void __stdcall OrphanRetStub_004136c0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00414770
void OrphanRetStub_00414770(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00430550
void OrphanRetStub_00430550(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004305c0
void OrphanRetStub_004305c0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00430bf0
void __stdcall OrphanRetStub_00430bf0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00430c10
void __stdcall OrphanRetStub_00430c10(int, int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0043d9f0
void OrphanRetStub_0043d9f0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0045acb0
void OrphanRetStub_0045acb0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0045ada0
void OrphanRetStub_0045ada0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0045d2a0
void __stdcall OrphanRetStub_0045d2a0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0047d5b0
void __stdcall OrphanRetStub_0047d5b0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0047df90
void __stdcall OrphanRetStub_0047df90(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0047f2b0
void __stdcall OrphanRetStub_0047f2b0(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0047f320
void __stdcall OrphanRetStub_0047f320(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0047f410
void __stdcall OrphanRetStub_0047f410(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0047fd70
int __stdcall ReturnFalseRuntimeSelectionAuxStatus(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004811e0
void __stdcall OrphanRetStub_004811e0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00481670
void __stdcall OrphanRetStub_00481670(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00481730
void __stdcall OrphanRetStub_00481730(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00481970
void __stdcall OrphanRetStub_00481970(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00481a30
void __stdcall OrphanRetStub_00481a30(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00481af0
void __stdcall OrphanRetStub_00481af0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00481d80
void __stdcall OrphanRetStub_00481d80(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00482010
void __stdcall OrphanRetStub_00482010(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004822e0
void OrphanRetStub_004822e0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00482420
void __stdcall OrphanRetStub_00482420(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00486530
void __stdcall OrphanRetStub_00486530(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00486550
void __stdcall OrphanRetStub_00486550(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004872e0
void __stdcall OrphanRetStub_004872e0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00487a00
void OrphanRetStub_00487a00(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00487f70
void __stdcall OrphanRetStub_00487f70(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00488800
void __stdcall OrphanRetStub_00488800(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00488820
void __stdcall OrphanRetStub_00488820(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00488b40
void __stdcall OrphanRetStub_00488b40(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00488e30
void __stdcall OrphanRetStub_00488e30(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00488e50
void __stdcall OrphanRetStub_00488e50(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00488e70
void __stdcall OrphanRetStub_00488e70(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004899a0
void __stdcall OrphanRetStub_004899a0(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00492d00
void __stdcall OrphanRetStub_00492d00(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00492d20
void __stdcall OrphanRetStub_00492d20(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00492d40
void __stdcall OrphanRetStub_00492d40(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00492d60
void __stdcall OrphanRetStub_00492d60(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0049bfb0
void OrphanRetStub_0049bfb0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0049e660
void __stdcall OrphanRetStub_0049e660(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0049e680
void __stdcall OrphanRetStub_0049e680(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004aad20
void OrphanRetStub_004aad20(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004ab800
void OrphanRetStub_004ab800(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b1410
void OrphanRetStub_004b1410(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b1990
void OrphanRetStub_004b1990(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b4210
void OrphanRetStub_004b4210(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b5160
void OrphanRetStub_004b5160(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b6f00
void OrphanRetStub_004b6f00(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b7c20
void OrphanRetStub_004b7c20(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b80a0
void OrphanRetStub_004b80a0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b8420
void OrphanRetStub_004b8420(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004be190
void __stdcall OrphanRetStub_004be190(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004be3f0
void __stdcall OrphanRetStub_004be3f0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004be410
void __stdcall OrphanRetStub_004be410(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004be430
void __stdcall OrphanRetStub_004be430(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004be6d0
void __stdcall OrphanRetStub_004be6d0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004bff60
void __stdcall OrphanRetStub_004bff60(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004c6fb0
void OrphanRetStub_004c6fb0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004c6fd0
void OrphanRetStub_004c6fd0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004cc470
void __stdcall OrphanRetStub_004cc470(int, int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d7e90
void __stdcall OrphanRetStub_004d7e90(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d7f80
void __stdcall OrphanRetStub_004d7f80(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d7fa0
void __stdcall OrphanRetStub_004d7fa0(int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d7fe0
void __stdcall OrphanRetStub_004d7fe0(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d8bc0
void OrphanRetStub_004d8bc0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d8be0
void __stdcall OrphanRetStub_004d8be0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004dca80
void __stdcall OrphanRetStub_004dca80(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004dcc30
void OrphanRetStub_004dcc30(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004de2b0
void OrphanRetStub_004de2b0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004e6610
void OrphanRetStub_004e6610(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004e7910
void __stdcall OrphanRetStub_004e7910(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004e7930
void __stdcall OrphanRetStub_004e7930(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004e7950
void __stdcall OrphanRetStub_004e7950(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004e7970
void OrphanRetStub_004e7970(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004e7ca0
void OrphanRetStub_004e7ca0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004f3220
void OrphanRetStub_004f3220(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004f5f90
void __stdcall OrphanRetStub_004f5f90(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004fed50
void __stdcall OrphanRetStub_004fed50(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00515de0
void __stdcall OrphanRetStub_00515de0(int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005328d0
void OrphanRetStub_005328d0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00534c20
int __stdcall ReturnZeroMissionVtableSlot2C(int, int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005354c0
void __stdcall OrphanRetStub_005354c0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00540aa0
void OrphanRetStub_00540aa0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00540b80
void OrphanRetStub_00540b80(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541880
void OrphanRetStub_00541880(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005418a0
void OrphanRetStub_005418a0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005418c0
void OrphanRetStub_005418c0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005418e0
void OrphanRetStub_005418e0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541900
void OrphanRetStub_00541900(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541920
void OrphanRetStub_00541920(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541940
void __stdcall OrphanRetStub_00541940(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541960
void OrphanRetStub_00541960(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541980
void OrphanRetStub_00541980(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005419a0
void OrphanRetStub_005419a0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005419c0
void OrphanRetStub_005419c0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541a40
void OrphanRetStub_00541a40(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541a60
void __stdcall OrphanRetStub_00541a60(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00541cb0
void __stdcall OrphanRetStub_00541cb0(int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00569d50
void OrphanRetStub_00569d50(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0056f460
void __stdcall OrphanRetStub_0056f460(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0056f480
void OrphanRetStub_0056f480(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005723d0
void OrphanRetStub_005723d0(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00574fc0
void __stdcall OrphanRetStub_00574fc0(int, int, int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0057b760
void OrphanRetStub_0057b760(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00596680
void __stdcall OrphanRetStub_00596680(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005966a0
void __stdcall OrphanRetStub_005966a0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005966c0
void __stdcall OrphanRetStub_005966c0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0059ad70
void OrphanRetStub_0059ad70(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0059ad90
void OrphanRetStub_0059ad90(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0059add0
void __stdcall OrphanRetStub_0059add0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x0059ae10
void OrphanRetStub_0059ae10(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x0059f710
void __stdcall OrphanRetStub_0059f710(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005a83c0
void __stdcall OrphanRetStub_005a83c0(int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005ad0d0
void __stdcall OrphanRetStub_005ad0d0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005ad0f0
void __stdcall OrphanRetStub_005ad0f0(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005b2860
void OrphanRetStub_005b2860(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005c2470
void OrphanRetStub_005c2470(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005c2610
void __stdcall OrphanRetStub_005c2610(int) {
  return;
}

// --- Constant-bool stubs: original is `xor al,al; ret[ N]` (return false) or
//     `mov al,1; ret[ N]` (return true). 1-byte bool return reproduces the
//     al-width load; FPO pragma above keeps ret N frameless. ---

// FUNCTION: IMPERIALISM 0x004d6730
bool ReturnFalseNationStateCapabilityFlag98(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d6750
bool ReturnFalseNationStateCapabilityFlag9C(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d6770
bool ReturnFalseNationStateCapabilityFlagA0(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d7b00
bool __stdcall ReturnFalseNationStateActionStub(int, int, int, int) {
  return false;
}

// FUNCTION: IMPERIALISM 0x004d7f60
bool __stdcall ReturnFalseNationStateCapabilityFlag90(int) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00534c00
bool ReturnFalseMissionVtableSlot28(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00534d30
bool __stdcall ReturnFalseMissionVtableSlot4C(int, int, int) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00534d50
bool ReturnFalseMissionVtableSlot50(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00534d70
bool ReturnFalseMissionVtableSlot54(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00534dd0
bool ReturnFalseMissionVtableSlot60(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00534df0
bool ReturnFalseMissionVtableSlot64(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00534f90
bool ReturnFalseMissionVtableSlot98(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x005354e0
bool ReturnTrueMissionCapabilityStub(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535500
bool ReturnFalseMissionCapabilityStub(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x005355b0
bool ReturnTrueForControlSeaZoneMissionCapabilityFlagA(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005355d0
bool ReturnFalseForControlSeaZoneMissionCapabilityFlagB(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00535640
bool ReturnTrueForScatteredShipsMissionCapabilityFlagA(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535660
bool ReturnTrueForScatteredShipsMissionCapabilityFlagB(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535680
bool ReturnTrueForScatteredShipsMissionSlot20(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005356f0
bool ReturnTrueForArmyMissionCapabilityFlag(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535790
bool ReturnTrueForDefendProvinceMissionCapabilityFlagA(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005357b0
bool ReturnTrueForDefendProvinceMissionCapabilityFlagB(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00539920
bool ReturnTrueForEscortMissionCapabilityFlagA(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00539940
bool ReturnFalseForEscortMissionCapabilityFlagB(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053a390
bool ReturnFalseForBeachheadMissionCapabilityFlagA(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053a3b0
bool ReturnFalseForBeachheadMissionCapabilityFlagB(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053aa50
bool ReturnFalseForBlockadePortMissionCapabilityFlagA(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053aa70
bool ReturnFalseForBlockadePortMissionCapabilityFlagB(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053c1b0
bool ReturnFalseForArmyAttackInvadeCapabilityFlag(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053d6f0
bool ReturnFalseForAttackProvinceMissionCapabilityFlag(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053f140
bool ReturnTrueForInvadeMissionCapabilityFlagAlt(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x0053f240
bool ReturnFalseForInvadeMissionCapabilityFlag(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053faa0
bool ReturnTrueForInvadeMissionCapabilityFlag(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005408c0
bool ReturnTrueNationStateCapabilityFlag98(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005408e0
bool ReturnTrueNationStateCapabilityFlagA0(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00540920
bool ReturnFalseProxyGreatPowerCapabilityStub(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00540f20
bool ReturnTrueNationStateCapabilityFlag9C(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005412b0
bool ReturnTrueNationStateCapabilityFlag98Alt(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005412d0
bool ReturnFalseNationStateCapabilityFlagA0Alt(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00541840
bool ReturnTrueNationStateCapabilityFlagA0Alt(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x00541860
bool ReturnFalseRemoteGreatPowerCapabilityStub(void) {
  return false;
}

// FUNCTION: IMPERIALISM 0x00541c90
bool ReturnTrueRemoteMinorCapabilityStub(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005e34b0
bool ReturnTrueRuntimeCredentialInitStub(void) {
  return true;
}

// FUNCTION: IMPERIALISM 0x005e3c00
bool ReturnTrueRuntimeCredentialFinalizeStub(void) {
  return true;
}

// --- More trivial stubs found by scanning autogen bodies (beyond the Stub/NoOp
//     names): bare ret / ret N, plus 8-bit (bool) and 16-bit (short) zero returns. ---

// FUNCTION: IMPERIALISM 0x00415030
void __stdcall ExecuteNoOpNewGameCommand(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00486990
void __stdcall HandleTurnEventViewportEdgeAutoScroll_Impl(int, int, int) {
  return;
}

// FUNCTION: IMPERIALISM 0x00489490
void DispatchTurnEventPacketWithCodeAndPayloadBuffer_Impl(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00489980
bool __stdcall OrphanLeaf_NoCall_Ins02_00489980(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00498c60
void RunOneTimeAnimationModalWaitAndInvalidateCityDialog_Impl(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x00498c80
void RunOneTimeAnimationModalWaitAndInvalidateCityDialog_Impl_At00498c80(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004b50e0
unsigned short OrphanLeaf_NoCall_Ins02_004b50e0(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d20c0
void NoOpCivilianMapInteractionManagerVirtualHook(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d4bd0
void __stdcall DiscardTileTokenArgumentAndReturn(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x004d7ee0
unsigned short __stdcall OrphanLeaf_NoCall_Ins02_004d7ee0(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f00
unsigned short OrphanLeaf_NoCall_Ins02_004d7f00(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f20
unsigned short __stdcall OrphanLeaf_NoCall_Ins02_004d7f20(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7f40
unsigned short __stdcall OrphanLeaf_NoCall_Ins02_004d7f40(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004d7fc0
bool __stdcall OrphanLeaf_NoCall_Ins02_004d7fc0(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004e0400
bool OrphanLeaf_NoCall_Ins02_004e0400(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005966e0
bool __stdcall OrphanLeaf_NoCall_Ins02_005966e0(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059adb0
void __stdcall TArmyTacUnit_VtblSlot00(int) {
  return;
}

// FUNCTION: IMPERIALISM 0x005aec80
void InitializeCityProductionState_Impl_At005aec80(void) {
  return;
}

// FUNCTION: IMPERIALISM 0x005e3490
bool __stdcall DefaultUnhandledTurnEventHookReturnsFalse(int) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00607bda
void TMacViewMgr_Slot22_Target(void) {
  return;
}
