#include "game/TQuickDrawSurfaceContext.h"

#include "game/gfx/CDib.h"
#include "game/gfx/TResourceMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00495cc0
TBitmapSurfaceNode::TBitmapSurfaceNode()
    : pixelBits(0), stride(0), bounds(0, 0, 0, 0), bitDepth(0), dib(0) {}

// FUNCTION: IMPERIALISM 0x00495d00
TBitmapSurfaceNode::TBitmapSurfaceNode(int width, int height, int bitDepth) {
  dib = new CDib(width, height, bitDepth);
  dib->CopyRgbQuadTableFrom(g_pResourceMgr->ResolveDefaultLogPalette());
  dib->BuildPaletteFromRgbQuadBuffer();
  dib->EnsureDibSectionCreated(nullptr);
  pixelBits = static_cast<unsigned char*>(dib->m_dibBits);
  stride = static_cast<short>((dib->m_pInfoHeader->bmiHeader.biWidth + 3) & ~3);
  CPoint dims;
  CPoint* d = dib->CopyBitmapDimensionsToPoint(&dims);
  bounds.left = 0;
  this->bitDepth = static_cast<short>(bitDepth);
  bounds.top = 0;
  bounds.right = d->x;
  bounds.bottom = d->y;
}
