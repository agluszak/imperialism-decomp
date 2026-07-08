#include "game/TEngineerDialog.h"

#include "decomp_types.h"
#include "game/global_data_tables.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"
#include "game/ui_widget_thunks.h"

// SYNTHETIC: IMPERIALISM 0x004d04b0
// TEngineerDialog::CreateObject

// SYNTHETIC: IMPERIALISM 0x004d0540
// TEngineerDialog::GetRuntimeClass

IMPLEMENT_DYNCREATE(TEngineerDialog, TView)

// FUNCTION: IMPERIALISM 0x004d0560
TEngineerDialog::TEngineerDialog() {
  this->field60 = 0;
  this->field64 = 0;
  this->field68 = 0;
}

// SYNTHETIC: IMPERIALISM 0x004d0590
// TEngineerDialog::`scalar deleting destructor'

TEngineerDialog::~TEngineerDialog() {}

// FUNCTION: IMPERIALISM 0x004d05e0
void TEngineerDialog::Free() {
  if (this->field60 != 0) {
    delete[] field60;
    field60 = 0;
  }
  if (this->field64 != 0) {
    delete[] field64;
    field64 = 0;
  }
  if (this->field68 != 0) {
    delete[] field68;
    this->field68 = 0;
  }
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x004d0650
void TEngineerDialog::ApplyRectSlot110(RECT* rectBuffer) {
  if (this->field60 == 0) {
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

  BlitQuickDrawSurfaces(reinterpret_cast<TQuickDrawBlitSurface*>(this->field60 + 4),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &headerRect,
                        &headerRect, 0);

  bodyY = 0x38;
  int bodyRowCount = (static_cast<short>(this->frameHeight38) - 0x46) / 0x0e;
  if (bodyRowCount > 0) {
    do {
      dstRect.top = bodyY;
      dstRect.bottom = bodyY + 0x0e;
      BlitQuickDrawSurfaces(reinterpret_cast<TQuickDrawBlitSurface*>(this->field68 + 4),
                            g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &bodyTileRect,
                            &dstRect, 0);
      bodyY = static_cast<short>(bodyY + 0x0e);
      bodyRowCount = bodyRowCount - 1;
    } while (bodyRowCount != 0);
  }

  dstRect.top = bodyY;
  dstRect.bottom = bodyY + 0x0e;
  BlitQuickDrawSurfaces(reinterpret_cast<TQuickDrawBlitSurface*>(this->field64 + 4),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &bodyTileRect, &dstRect,
                        0);

  (void)rectBuffer;
}
