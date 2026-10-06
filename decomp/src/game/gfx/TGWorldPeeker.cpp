#include "game/gfx/TGWorldPeeker.h"

#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TQuickDrawSurfaceContext.h"

// FUNCTION: IMPERIALISM 0x004ff2b0
TGWorldPeeker::~TGWorldPeeker() {}

IMPLEMENT_DYNCREATE(TGWorldPeeker, TView)
// FUNCTION: IMPERIALISM 0x004ff2f0
void TGWorldPeeker::Draw(RECT* rectBuffer) {
  if (peekSurface != nullptr) {
    ResetQuickDrawStrokeState();
    BlitRectWithOptionalTransparency(peekSurface->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), rectBuffer,
                                     rectBuffer, 0, 0);
  }
}
