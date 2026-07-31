#include "game/ui_widgets/TCivilianButton.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/map/TMapMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/military/TCivUnit.h"
#include "game/ui_core/TControl.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_core/TViewMgr.h"
#include "game/mfc.h"
// SYNTHETIC: IMPERIALISM 0x0058b340
// TCivilianButton::CreateObject
// SYNTHETIC: IMPERIALISM 0x0058b3c0
// TCivilianButton::GetRuntimeClass

IMPLEMENT_DYNCREATE(TCivilianButton, TRadioPictureButton)

// FUNCTION: IMPERIALISM 0x0058b3e0
TCivilianButton::TCivilianButton() : TRadioPictureButton() {
  this->eventNumber60 = 0xc;
}

// Destructors are compiler-generated (implicit) from real inheritance.

// SYNTHETIC: IMPERIALISM 0x0058b410
// TCivilianButton::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0058b440
TCivilianButton::~TCivilianButton() {}

// FUNCTION: IMPERIALISM 0x0058b460
void TCivilianButton::SetSelectedCivilianOrderAndEnableButton(TCivUnit* selectedOrder) {
  this->eventNumber60 = 0xc;
  this->selectedCivilianOrder9c = selectedOrder;
  if (selectedOrder != 0) {
    Show(1, 0);
    ViewEnable(1, 0);

    short mappedValue = g_pGlobalMapState->ApplyMapImprovementSelectionState(selectedOrder);
    this->mappedSelection98 = mappedValue;
    return;
  }
  Show(0, 1);
}

// FUNCTION: IMPERIALISM 0x0058b4f0
void TCivilianButton::Draw(RECT* rectBuffer) {
  (void)rectBuffer;
  if (ownerContext != 0) {
    TPicture::Draw(nullptr);
  }
  UpdatePaletteIndexWithDefaultFallback(0x10);

  RECT srcRect;
  srcRect.left = mappedSelection98;
  srcRect.top = 0;
  srcRect.right = srcRect.left + 0x40;
  srcRect.bottom = 0x40;

  RECT dstRect = {0, 2, 0x40, 0x42};
  TQuickDrawSurfaceContext* hintSource = g_pMacViewMgr->atlas66c;
  BlitQuickDrawSurfaces(hintSource->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect, &dstRect,
                        0x24);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}
