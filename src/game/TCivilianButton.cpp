#include "game/TCivilianButton.h"
#include "game/TAmtBar.h"
#include "game/TPicture.h"
#include "game/global_data_tables.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TControl.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/UiRuntimeContext.h"
#include "game/mfc.h"
const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;

// SYNTHETIC: IMPERIALISM 0x0058b340
// TCivilianButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058b3c0
// TCivilianButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivilianButton, TRadioPictureButton)

// FUNCTION: IMPERIALISM 0x0058b3e0
TCivilianButton::TCivilianButton() : TRadioPictureButton() {
  this->frameStyle60 = 0xc;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x0058b410
// TCivilianButton::`scalar deleting destructor'
TCivilianButton::~TCivilianButton() {}

// FUNCTION: IMPERIALISM 0x0058b460
void TCivilianButton::SetSelectionAndEnableByMappedValue(int selectedValue) {
  this->frameStyle60 = 0xc;
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
    TPicture::ApplyRectSlot110(nullptr);
  }
  UpdatePaletteIndexWithDefaultFallback(0x10);

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
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

#if defined(_MSC_VER)
#pragma auto_inline(on)
#endif
