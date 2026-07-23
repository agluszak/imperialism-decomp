#include "game/TQuickDrawSurfaceContext.h"

#include "game/CDib.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"

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
  field08 = 0;
  bitDepth18 = static_cast<short>(bitDepth);
  field0c = 0;
  pixelWidth10 = d->x;
  pixelHeight14 = d->y;
}
