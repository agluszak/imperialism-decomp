#include "game/TQuickDrawSurfaceContext.h"

#include "game/gfx/CDib.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00495cc0
TBitmapSurfaceNode::TBitmapSurfaceNode()
    : pixelBits(0), stride(0), bounds(0, 0, 0, 0), bitDepth18(0), dib(0) {}

// Constructor of the QuickDraw bitmap-surface node: `new`s a backing CDib(width, height,
// bitDepth), seeds its color table from the module cache's shared default LOGPALETTE, builds
// the palette + DIB section, and caches the pixel bits / dword-aligned stride / dimensions.
// Real __thiscall ctor (returns `this`); reached as `new TBitmapSurfaceNode(...)` from
// TBitmapSurfaceContextDescriptor::InitializeSurfaceNode (0x495eb0). The +0x18 field stores
// the low 16 bits of `bitDepth` (a 16-bit write), not a height.
// FUNCTION: IMPERIALISM 0x00495d00
TBitmapSurfaceNode::TBitmapSurfaceNode(int width, int height, int bitDepth) {
  dib = new CDib(width, height, bitDepth);
  dib->CopyRgbQuadTableFrom(g_pModuleLibraryCacheState->ResolveDefaultLogPalette());
  dib->BuildPaletteFromRgbQuadBuffer();
  dib->EnsureDibSectionCreated(nullptr);
  pixelBits = static_cast<unsigned char*>(dib->m_dibBits);
  stride = static_cast<short>((dib->m_pInfoHeader->bmiHeader.biWidth + 3) & ~3);
  CPoint dims;
  CPoint* d = dib->CopyBitmapDimensionsToPoint(&dims);
  bounds.left = 0;
  bitDepth18 = static_cast<short>(bitDepth);
  bounds.top = 0;
  bounds.right = d->x;
  bounds.bottom = d->y;
}
