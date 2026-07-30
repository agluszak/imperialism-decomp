#include "game/TQuickDrawSurfaceContext.h"

#include "game/gfx/CDib.h"

// FUNCTION: IMPERIALISM 0x00495fd0
TQuickDrawSurfaceContext::~TQuickDrawSurfaceContext() {
  TBitmapSurfaceNode** slot = static_cast<TBitmapSurfaceNode**>(blitSurface.surfaceObject);
  if (slot != nullptr) {
    TBitmapSurfaceNode* node = *slot;
    if (node != nullptr) {
      delete node->dib;
      delete node;
    }
    delete slot;
  }
  blitSurface.surfaceObject = nullptr;
  blitSurface.pixelBits = 0;
  blitSurface.stride = 0;
  blitSurface.pad06 = 0;
  blitSurface.surfaceDib = 0;
}
