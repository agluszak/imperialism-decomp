#pragma once

// Shared free-function thunk declarations for the widget / trade-screen
// ecosystem. These are the ABI bridges and lifecycle hooks that the widget
// class files and TradeScreenRuntimeBridge route through. Extracted from
// ui_widget_shared.h.

#include "decomp_types.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
unsigned int __cdecl thunk_GetActiveNationId(void);
undefined4 thunk_NoOpUiLifecycleHook(void);
undefined4 thunk_HandleCityDialogToggleCommandOrForward(void);
undefined4 thunk_HandleCursorHoverSelectionByChildHitTestAndFallback(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
undefined4 thunk_ConstructUiResourceEntryType4B0C0(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
void __fastcall InitializeTradeMoveAndBarControls(void* context, int unusedEdx = 0,
                                                  unsigned int styleSeed = 0);
undefined4 thunk_GetCityBuildingProductionValueBySlot(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);
undefined4 thunk_DestructTShipAndFreeIfOwned(void);
undefined4 thunk_InitializeUiTextStyleDescriptor(void);
