#pragma once

#include "decomp_types.h"
#include "game/TControl.h"
#include "game/TUberCluster.h"
#include "game/TView.h"
#include "game/TControl.h"
#include "game/UiRuntimeContext.h"
#include "game/win_rect.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"

// Include the new split headers
#include "game/TCivilianButton.h"
#include "game/THQButton.h"
#include "game/TPlacard.h"
#include "game/TArmyPlacard.h"
#include "game/TCombatReportView.h"
#include "game/TNumberedArrowButton.h"

#include <new>

typedef TCivilianButton CivilianButtonState;
typedef THQButton HQButtonState;
typedef TPlacard PlacardState;
typedef TCombatReportView CombatReportViewState;
typedef TNumberedArrowButton NumberedArrowButtonState;

namespace {

static const int kControlTagPlus = 0x706c7573;
static const int kControlTagMinu = 0x6d696e75;
static const unsigned int kAddrCityOrderCapabilityState = 0x006A43D8;

class TradeScreenRuntimeBridge {
public:
  static __inline void ConstructTUberClusterObject(void* self) {
    new (self) TUberCluster();
  }

  static __inline void ConstructUiResourceEntryType4B0C0(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiResourceEntryType4B0C0)(self);
  }

  static __inline void ConstructUiClickablePictureResourceEntry(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiClickablePictureResourceEntry)(
        self);
  }

  static __inline void InitializeTradeMoveAndBarControls(void* self) {
    ::InitializeTradeMoveAndBarControls(self);
  }

  static __inline int GetCityBuildingProductionValueBySlot(void* cityState, short slot) {
    return (int)reinterpret_cast<undefined4(__fastcall*)(void*, short)>(
        ::thunk_GetCityBuildingProductionValueBySlot)(cityState, slot);
  }

  static __inline void DestructCityDialogSharedBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

static __inline short QueryActiveNationId(void) {
  return (short)thunk_GetActiveNationId();
}

} // namespace
