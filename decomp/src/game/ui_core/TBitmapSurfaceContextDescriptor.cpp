#include "game/TQuickDrawSurfaceContext.h"

#include "game/gfx/CDib.h"
#include "game/mfc.h"

namespace {

const char kQuickDrawDebugSourcePath[] = "D:\\Ambit\\QuickDraw.cpp";

} // namespace

// FUNCTION: IMPERIALISM 0x00495e20
TBitmapSurfaceContextDescriptor::TBitmapSurfaceContextDescriptor() {
  field00 = 0;
  blitSurface.pixelBits = 0;
  blitSurface.stride = 0;
  blitSurface.clipRect.left = 0;
  blitSurface.clipRect.top = 0;
  blitSurface.clipRect.right = 0;
  blitSurface.clipRect.bottom = 0;
  blitSurface.field18 = 0;
  blitSurface.surfaceDib = 0;
  blitSurface.surfaceObject = 0;
  blitSurface.foregroundColor = 0;
  blitSurface.backgroundColor = 0;

  blitSurface.clipRect.left = 0;
  blitSurface.clipRect.top = 0;
  blitSurface.clipRect.right = 0;
  blitSurface.clipRect.bottom = 0;
  blitSurface.pixelBits = 0;
  blitSurface.stride = 0;
  blitSurface.surfaceDib = 0;
  debugSourcePath = kQuickDrawDebugSourcePath;
}

// FUNCTION: IMPERIALISM 0x00495eb0
bool TBitmapSurfaceContextDescriptor::InitializeSurfaceNode(int width, int height, int bitDepth) {
  SetPixMapHandle(new TBitmapSurfaceNode*);
  *GetPixMapHandle() = new TBitmapSurfaceNode(width, height, bitDepth);

  blitSurface.pixelBits = static_cast<unsigned char*>((*GetPixMapHandle())->dib->m_dibBits);
  blitSurface.stride =
      static_cast<short>(((*GetPixMapHandle())->dib->m_pInfoHeader->bmiHeader.biWidth + 3) & ~3);
  CPoint dims;
  CPoint* d = (*GetPixMapHandle())->dib->CopyBitmapDimensionsToPoint(&dims);
  blitSurface.clipRect.left = 0;
  blitSurface.clipRect.top = 0;
  blitSurface.clipRect.right = d->x;
  blitSurface.clipRect.bottom = d->y;
  blitSurface.surfaceDib = (*GetPixMapHandle())->dib;
  return *GetPixMapHandle() != NULL;
}

// FUNCTION: IMPERIALISM 0x00496420
void DisposeGWorld(TQuickDrawSurfaceContext* surface) {
  delete surface;
}
