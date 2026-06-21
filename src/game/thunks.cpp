// Manual decompilation file.
// Use tools/workflow/promote_from_autogen.py to seed functions from autogen.

#include "decomp_types.h"
#include "game/CString.h"
#include "game/mcappui_globals.h"

undefined4 RefreshStrategicMapStatusIconsForActiveNation(void);
undefined4 HandleTurnEventDialogFactorySlotB4(void);
undefined4 HandleTurnEventF3D_PopulateRecentTurnMessages(void);
void thunk_HandleStartupCommand100(void);
undefined4 HandleTurnEventVtableSlot88BuildStatusText(void);
undefined4 HandleStartupCommand100(void);
undefined4 NoOpTurnEventStateVtableSlot8C(void);
undefined4 InvokeStrategicMapViewMethod5C(void);

undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);

// These two targets are not yet exported as user-defined symbols from Ghidra.
// Keep temporary local placeholders so thunk wrappers remain linkable.
static undefined4 Missing_HandleTurnEventDialogFactorySlotDC(void) {
  return 0;
}

static undefined4 Missing_GetCivilianMapManagerTypeName(void) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00401064
void thunk_RefreshStrategicMapStatusIconsForActiveNation(void) {
  RefreshStrategicMapStatusIconsForActiveNation();
}

// FUNCTION: IMPERIALISM 0x004011a9
void thunk_HandleTurnEventDialogFactorySlotDC(void) {
  Missing_HandleTurnEventDialogFactorySlotDC();
}

// FUNCTION: IMPERIALISM 0x00401244
void thunk_HandleTurnEventDialogFactorySlotB4(void) {
  HandleTurnEventDialogFactorySlotB4();
}

// FUNCTION: IMPERIALISM 0x004012b2
void thunk_HandleTurnEventF3D_PopulateRecentTurnMessages(void) {
  HandleTurnEventF3D_PopulateRecentTurnMessages();
}

// FUNCTION: IMPERIALISM 0x0040132a
void thunk_DispatchStartupCommand100ToAppSingleton(void) {
  thunk_HandleStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x0040154b
void thunk_DestructBuildingExpansionViewAndMaybeFree(void) {}

// FUNCTION: IMPERIALISM 0x004017b7
void thunk_HandleTurnEventVtableSlot88BuildStatusText(void) {
  HandleTurnEventVtableSlot88BuildStatusText();
}

// FUNCTION: IMPERIALISM 0x00401816
void thunk_GetCivilianMapManagerTypeName(void) {
  Missing_GetCivilianMapManagerTypeName();
}

// FUNCTION: IMPERIALISM 0x004019fb
void thunk_HandleStartupCommand100(void) {
  HandleStartupCommand100();
}

// FUNCTION: IMPERIALISM 0x00401b09
void thunk_NumericEntryMethod_00401b09(void) {}

// FUNCTION: IMPERIALISM 0x00401b72
void thunk_ApplyCityDialogMinisterValues(void) {}

// FUNCTION: IMPERIALISM 0x00401cdf
void thunk_NoOpTurnEventStateVtableSlot8C(void) {
  NoOpTurnEventStateVtableSlot8C();
}

// FUNCTION: IMPERIALISM 0x00401ed8
void thunk_InvokeStrategicMapViewMethod5C(void) {
  InvokeStrategicMapViewMethod5C();
}

// Compatibility aliases for thunk names that were renamed in recent exports.
// Keep these minimal so existing manual files continue to link.

undefined4 GetOrCreateMfcModuleThreadState(void) {
  return 0;
}

// thunk_DestructEngineerDialogBaseState (0x405c72) and
// thunk_InitializeTradeMoveAndBarControls (0x4080c6) are now provided by the autogen
// stubs after the Ghidra autogen refresh; the legacy aliases here are removed to avoid
// duplicate-symbol link errors.

undefined4 thunk_DestructTShipAndFreeIfOwned(void) {
  return 0;
}

undefined4 thunk_QueueInterNationEventRecordDeduped(void) {
  return 0;
}

undefined4 thunk_RenderCivilianTargetLegendVariantA(void) {
  return 0;
}

undefined4 thunk_RenderCivilianTargetLegendVariantB(void) {
  return 0;
}

undefined4 thunk_BuildCivReportNationEntryDetailTextBlock(void) {
  return 0;
}
