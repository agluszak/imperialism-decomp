#include "game/TCivilianButton.h"
#include "game/TAmtBar.h"
#include "game/TPictureResourceEntryBase.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TControl.h"
#include "game/trade_quickdraw.h"
#include "game/UiRuntimeContext.h"
#include "game/CRuntimeClass.h"

CRuntimeClass g_pClassDescTCivilianButton = {nullptr, 0, 0, nullptr, nullptr};

const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;
const unsigned int kAddrSfxPlaybackSystem = 0x006a4510;

#if defined(_MSC_VER)
#pragma auto_inline(off)
#endif

// FUNCTION: IMPERIALISM 0x00571620
void TCivilianButton::SetControlStateFlagAndMaybeRefresh(bool enabledState, bool refreshNow) {
  char mode = enabledState ? 1 : 0;
  if (mode != static_cast<char>(commandTagResourceByte)) {
    commandTagResourceByte = static_cast<unsigned char>(mode);
    short bitmapId =
        mode == 0 ? static_cast<short>(glyphBase84 - 1) : static_cast<short>(glyphBase84 + 1);
    reinterpret_cast<TAmtBar*>(this)->SetBitmap(bitmapId, 1);
    if (refreshNow) {
      RefreshControl();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005716b0
void TCivilianButton::BeginMouseCaptureAndStartRepeatTimer(Point32* point) {
  int sfxSystem = *reinterpret_cast<int*>(kAddrSfxPlaybackSystem);
  reinterpret_cast<void(__cdecl*)(int, int, int)>(
      *reinterpret_cast<void**>(*reinterpret_cast<int*>(sfxSystem) + 0xb8))(
      timingWord92, 0, 1);
  TView::BeginMouseCaptureAndStartRepeatTimer(point);
}

// FUNCTION: IMPERIALISM 0x00571850
void TCivilianButton::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    if (commandTagResourceByte == 0) {
      reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(1, 0);
    }
    TControl::HandleEvent(commandId, sourceHandler, event);
    return;
  }
  if (commandId != 0x1f) {
    if (commandId != 0x20) {
      TControl::HandleEvent(commandId, sourceHandler, event);
      return;
    }
    reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(0, 0);
    return;
  }
  reinterpret_cast<TAmtBar*>(this)->InvokeSlot1CC(1, 0);
}

// FUNCTION: IMPERIALISM 0x0058b340
void* __cdecl CreateTCivilianButtonInstance(void) {
  return new TCivilianButton();
}

// FUNCTION: IMPERIALISM 0x0058b3c0
CRuntimeClass* TCivilianButton::GetRuntimeClass() {
  return &g_pClassDescTCivilianButton;
}

// FUNCTION: IMPERIALISM 0x0058b3e0
TCivilianButton::TCivilianButton() : TRadioPictureButton() {
  this->hasCommandTagResource = 0xc;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058b410
// TCivilianButton::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058b460
void TCivilianButton::SetSelectionAndEnableByMappedValue(int selectedValue) {
  this->hasCommandTagResource = 0xc;
  this->selectedValue9c = (short)selectedValue;
  if (selectedValue != 0) {
    SetEnabled(1, 0);
    SetState(1, 0);

    char* globalMapState = reinterpret_cast<char**>(0x00693a10)[0];
    short mappedValue = reinterpret_cast<short(__fastcall*)(int)>(
        *reinterpret_cast<int*>(globalMapState + 0x118))(selectedValue);
    this->mappedSelection98 = mappedValue;
    return;
  }
  SetEnabled(0, 1);
}

// FUNCTION: IMPERIALISM 0x0058b4f0
void TCivilianButton::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
  if (ownerContext != 0) {
    TPictureResourceEntryBase::ApplyRectSlot110(nullptr);
  }
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);

  RECT srcRect;
  srcRect.left = mappedSelection98;
  srcRect.top = 0;
  srcRect.right = srcRect.left + 0x40;
  srcRect.bottom = 0x40;

  RECT dstRect = {0, 2, 0x40, 0x42};
  int strategicMapViewSystem = *reinterpret_cast<int*>(kAddrStrategicMapViewSystem);
  TQuickDrawSurfaceContext* hintSource = reinterpret_cast<TQuickDrawSurfaceContext*>(
      *reinterpret_cast<int*>(strategicMapViewSystem + 0x66c));
  BlitQuickDrawSurfaces(hintSource->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &dstRect,
                        0x24);
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif

TCivilianButton::~TCivilianButton() {}
