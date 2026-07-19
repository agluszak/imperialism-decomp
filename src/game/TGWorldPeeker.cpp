#include "game/TGWorldPeeker.h"

#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"

// SYNTHETIC: IMPERIALISM 0x004ff280
// TGWorldPeeker::`scalar deleting destructor'
TGWorldPeeker::~TGWorldPeeker() {}
// SYNTHETIC: IMPERIALISM 0x004ff1f0
// TGWorldPeeker::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ff2d0
// TGWorldPeeker::GetRuntimeClass

IMPLEMENT_DYNCREATE(TGWorldPeeker, TView)

TGWorldPeeker::TGWorldPeeker() : field60(nullptr) {}

// FUNCTION: IMPERIALISM 0x004ff2f0
void TGWorldPeeker::ApplyRectSlot110(RECT* rectBuffer) {
  if (field60 != nullptr) {
    ResetQuickDrawStrokeState();
    BlitRectWithOptionalTransparency(field60->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), rectBuffer,
                                     rectBuffer, 0, 0);
  }
}
