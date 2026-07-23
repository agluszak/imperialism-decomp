#include "game/TQuickDrawSurfaceContext.h"

#include "game/gfx/CDib.h"
#include "game/mfc.h"

namespace {

const char kQuickDrawDebugSourcePath[] = "D:\\Ambit\\QuickDraw.cpp";

} // namespace

// The original is the real descriptor constructor: NewGWorld allocates 0x34 bytes and
// invokes this entry under an EH construction state before publishing the GWorld.
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

  // The Windows QuickDraw constructor repeats the CGrafPort-facing defaults after
  // initializing its PixMap-handle and color state.
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

  // Original (0x495eb0): +0x4 = dib bits pointer, +0x8 = (biWidth + 3) & ~3 as a 16-bit
  // stride, clip rect = the CDib's own width/height (re-read through
  // CopyBitmapDimensionsToPoint, not the cached node fields), +0x20 = the CDib itself. The
  // node is re-read through the slot each time (no cached local), matching the original.
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
  return *GetPixMapHandle() != nullptr;
}

// FUNCTION: IMPERIALISM 0x00495fd0
void TBitmapSurfaceContextDescriptor::ReleaseSurfaceNode() {
  TBitmapSurfaceNode** slot = GetPixMapHandle();
  if (slot != nullptr) {
    TBitmapSurfaceNode* node = *slot;
    if (node != nullptr) {
      delete node->dib;
      delete node;
    }
    delete slot;
  }
  SetPixMapHandle(nullptr);
  blitSurface.pixelBits = 0;
  blitSurface.stride = 0;
  blitSurface.pad06 = 0;
  blitSurface.surfaceDib = 0;
}
