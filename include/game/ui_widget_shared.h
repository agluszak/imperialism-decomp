#pragma once

// Shared UI-wrapper scaffolding extracted from widget class files.

#include "decomp_types.h"
#include "game/TControl.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);
unsigned int __cdecl thunk_GetActiveNationId(void);
undefined4 thunk_NoOpUiLifecycleHook(void);
undefined4 thunk_HandleCityDialogToggleCommandOrForward(void);
undefined4 thunk_HandleCursorHoverSelectionByChildHitTestAndFallback(void);
undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
undefined4 thunk_ConstructUiClickablePictureResourceEntry(void);
undefined4 thunk_ConstructPictureResourceEntryBase(void);
undefined4 thunk_DestructEngineerDialogBaseState(void);
undefined4 thunk_DestructCityDialogSharedBaseState(void);

namespace {

static const int kControlTagPlus = 0x706c7573;
static const int kControlTagMinu = 0x6d696e75;
static const unsigned int kAddrCityOrderCapabilityState = 0x006A43D8;

static char g_vtblTCivilianButton;
static char g_pClassDescTCivilianButton;
static char g_vtblTHQButton;
static char g_pClassDescTHQButton;
static char g_vtblTPlacard;
static char g_pClassDescTPlacard;
static char g_vtblTArmyPlacard;
static char g_pClassDescTArmyPlacard;
static char g_vtblTNumberedArrowButton;
static char g_pClassDescTNumberedArrowButton;
static char g_vtblTCombatReportView;
static char g_pClassDescTCombatReportView;

struct TradeControl {
  void* vftable;
  char pad_04[0x18];
  int controlTag;
  char pad_20[0x64];
  short bitmapId;

  __inline char IsActionable();
  __inline void SetBitmap(int bitmapIdValue, int unknownFlag);
  __inline void QueryBounds(int* boundsBuffer);
  __inline void InvokeSlotE4();
  __inline void InvokeSlot1CC(int value, int modeFlag);
};

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

static __inline char CallIsActionableSlotEC(TradeControl* control) {
  return reinterpret_cast<char(__fastcall*)(TradeControl*)>(
      (*reinterpret_cast<void***>(control))[0xec / 4])(control);
}

static __inline void CallSetBitmapSlot1C8(TradeControl* control, int bitmapIdValue,
                                          int unknownFlag) {
  reinterpret_cast<void(__fastcall*)(TradeControl*, int, int)>(
      (*reinterpret_cast<void***>(control))[0x1c8 / 4])(control, bitmapIdValue, unknownFlag);
}

static __inline void CallQueryBoundsSlot12C(TradeControl* control, int* boundsBuffer) {
  reinterpret_cast<void(__fastcall*)(TradeControl*, int*)>(
      (*reinterpret_cast<void***>(control))[0x12c / 4])(control, boundsBuffer);
}

static __inline void CallCtrlSlot57(TradeControl* control) {
  reinterpret_cast<void(__fastcall*)(TradeControl*)>(
      (*reinterpret_cast<void***>(control))[0xe4 / 4])(control);
}

static __inline void CallInvokeSlot1CC(TradeControl* control, int value, int modeFlag) {
  reinterpret_cast<void(__fastcall*)(TradeControl*, int, int)>(
      (*reinterpret_cast<void***>(control))[0x1cc / 4])(control, value, modeFlag);
}

class TradeScreenRuntimeBridge {
public:
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

  static __inline void DestructCityDialogSharedBaseState(void* self) {
    reinterpret_cast<void(__fastcall*)(void*)>(::thunk_DestructCityDialogSharedBaseState)(self);
  }
};

__inline char TradeControl::IsActionable() {
  return CallIsActionableSlotEC(this);
}

__inline void TradeControl::SetBitmap(int bitmapIdValue, int unknownFlag) {
  CallSetBitmapSlot1C8(this, bitmapIdValue, unknownFlag);
}

__inline void TradeControl::QueryBounds(int* boundsBuffer) {
  CallQueryBoundsSlot12C(this, boundsBuffer);
}

__inline void TradeControl::InvokeSlotE4() {
  CallCtrlSlot57(this);
}

__inline void TradeControl::InvokeSlot1CC(int value, int modeFlag) {
  CallInvokeSlot1CC(this, value, modeFlag);
}

static __inline short QueryActiveNationId(void) {
  return (short)thunk_GetActiveNationId();
}

} // namespace
