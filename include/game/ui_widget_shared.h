#pragma once

// Shared UI-wrapper scaffolding for the widget class files.
//
// The globally-named scaffolding (UI runtime context, RECT helpers, QuickDraw
// guards, the loose ABI thunks, and the now-global TradeControl) has been split
// into focused headers and is re-exported here. The per-widget state structs,
// their vtable/class-descriptor address placeholders, the runtime bridge, and
// the local constants stay in this header's anonymous namespace: MSVC500 keys
// anonymous-namespace mangling on the defining file, so relocating them to other
// files would rename every factory/ctor symbol and desync it from the recovered
// symbol database. They remain here until that database is re-synced.

#include "decomp_types.h"
#include "game/TControl.h"
#include "game/TView.h"
#include "game/TradeControl.h"
#include "game/UiRuntimeContext.h"
#include "game/win_rect.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"

namespace {

static const int kControlTagPlus = 0x706c7573;
static const int kControlTagMinu = 0x6d696e75;
static const unsigned int kAddrCityOrderCapabilityState = 0x006A43D8;

// GLOBAL: IMPERIALISM 0x666da8
static char g_vtblTCivilianButton;
// GLOBAL: IMPERIALISM 0x663040
static char g_pClassDescTCivilianButton;
// GLOBAL: IMPERIALISM 0x666fe0
static char g_vtblTHQButton;
// GLOBAL: IMPERIALISM 0x663058
static char g_pClassDescTHQButton;
// GLOBAL: IMPERIALISM 0x667218
static char g_vtblTPlacard;
// GLOBAL: IMPERIALISM 0x663070
static char g_pClassDescTPlacard;
// GLOBAL: IMPERIALISM 0x667448
static char g_vtblTArmyPlacard;
// GLOBAL: IMPERIALISM 0x663088
static char g_pClassDescTArmyPlacard;
// GLOBAL: IMPERIALISM 0x667678
static char g_vtblTNumberedArrowButton;
// GLOBAL: IMPERIALISM 0x6630a0
static char g_pClassDescTNumberedArrowButton;
// GLOBAL: IMPERIALISM 0x6678a0
static char g_vtblTCombatReportView;
// GLOBAL: IMPERIALISM 0x6630b8
static char g_pClassDescTCombatReportView;

struct CivilianButtonState {
  void* vftable;
  char pad_04[0x5c];
  int buttonTag;
};

struct HQButtonState {
  void* vftable;
  char pad_04[0x5c];
  int buttonTag;
  unsigned char toggleStateAt64;
  char pad_65[0x1f];
  short glyphBase84;
  char pad_86[0xa];
  short glyph90;
  short glyph92;
  short glyph94;
  short glyph96;
  short glyph98;
  char pad_9a[2];
};

struct PlacardState {
  void* vftable;
  char pad_04[0x8c];
  short placardValue;

  void WrapperFor_thunk_NoOpUiLifecycleHook_At0058bab0();
  void WrapperFor_thunk_InvalidateCityDialogRectRegion_At0058bb50(int arg1, int arg2);
  void RenderPlacardValueTextWithShadow();
};

struct NumberedArrowButtonState {
  void* vftable;
  char pad_04[0x34];
  int width38;
  char pad_3c[0x12];
  short hoverTag4e;
  char pad_50[0x34];
  short value84;
  short value86;
};

struct CombatReportViewState {
  void* vftable;
  char pad_04[0x9c];
};

class TradeScreenRuntimeBridge {
public:
  static __inline void ConstructTUberClusterBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::ConstructTUberClusterBaseState)(self);
  }

  static __inline void ConstructUiResourceEntryBase(void* self) {
    reinterpret_cast<TView*>(self)->thunk_ConstructUiResourceEntryBase();
  }

  static __inline void ConstructUiResourceEntryType4B0C0(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiResourceEntryType4B0C0)(self);
  }

  static __inline void ConstructUiClickablePictureResourceEntry(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructUiClickablePictureResourceEntry)(
        self);
  }

  static __inline void ConstructUiCommandTagResourceEntryBase(void* self) {
    reinterpret_cast<TControl*>(self)->thunk_ConstructUiCommandTagResourceEntryBase();
  }

  static __inline void ConstructPictureResourceEntryBase(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_ConstructPictureResourceEntryBase)(self);
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
