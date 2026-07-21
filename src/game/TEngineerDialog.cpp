#include "game/TEngineerDialog.h"

#include "decomp_types.h"
#include "game/global_data_tables.h"
#include "game/TDisplayMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"

// SYNTHETIC: IMPERIALISM 0x004d04b0
// TEngineerDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x004d0540
// TEngineerDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEngineerDialog, TView)

// FUNCTION: IMPERIALISM 0x004d0560
TEngineerDialog::TEngineerDialog() {
  this->headerSurface60 = 0;
  this->footerSurface64 = 0;
  this->bodyTileSurface68 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004d0590
// TEngineerDialog::`scalar deleting destructor'

TEngineerDialog::~TEngineerDialog() {}

// FUNCTION: IMPERIALISM 0x004d05e0
void TEngineerDialog::Free() {
  if (this->headerSurface60 != 0) {
    g_pDisplayMgr->RemoveGWorld(headerSurface60);
  }
  if (this->footerSurface64 != 0) {
    g_pDisplayMgr->RemoveGWorld(footerSurface64);
  }
  if (this->bodyTileSurface68 != 0) {
    g_pDisplayMgr->RemoveGWorld(bodyTileSurface68);
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x004d0650
void TEngineerDialog::ApplyRectSlot110(RECT* rectBuffer) {
  if (this->headerSurface60 == 0) {
    return;
  }

  RECT headerRect;
  RECT bodyTileRect;
  RECT dstRect;
  short bodyY;

  headerRect.left = 0;
  headerRect.top = 0;
  headerRect.right = 0x148;
  headerRect.bottom = 0x38;
  bodyTileRect.left = 0;
  bodyTileRect.top = 0;
  bodyTileRect.right = 0x148;
  bodyTileRect.bottom = 0x0e;
  dstRect.left = 0;
  dstRect.right = 0x148;

  BlitQuickDrawSurfaces(this->headerSurface60->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &headerRect,
                        &headerRect, 0);

  bodyY = 0x38;
  int bodyRowCount = (static_cast<short>(this->frameHeight38) - 0x46) / 0x0e;
  if (bodyRowCount > 0) {
    do {
      dstRect.top = bodyY;
      dstRect.bottom = bodyY + 0x0e;
      BlitQuickDrawSurfaces(this->bodyTileSurface68->GetBlitSurface(),
                            g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &bodyTileRect,
                            &dstRect, 0);
      bodyY = static_cast<short>(bodyY + 0x0e);
      bodyRowCount = bodyRowCount - 1;
    } while (bodyRowCount != 0);
  }

  dstRect.top = bodyY;
  dstRect.bottom = bodyY + 0x0e;
  BlitQuickDrawSurfaces(this->footerSurface64->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &bodyTileRect, &dstRect,
                        0);

  (void)rectBuffer;
}
