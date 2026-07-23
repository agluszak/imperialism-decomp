#include "game/TPicture.h"

#include "game/CDib.h"
#include "game/CDibPal.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TView.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// Scratch (width, height) pair the SetPictureResourceIdAndRefresh fallback path builds
// and immediately discards (the original never reads it back either -- confirmed via
// the raw listing: no instruction between this call and the function's return
// references the buffer again).
struct PictureFallbackSizeScratch {
  int width;
  int height;

  void Set(int newWidth, int newHeight);
};

// SYNTHETIC: IMPERIALISM 0x0048eeb0
// TPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048efa0
// TPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPicture, TControl)

// FUNCTION: IMPERIALISM 0x0048efc0
TPicture::TPicture()
    : TControl(), glyphBase84(-1), reserved86(0), bitmapId(0), resourceNamespaceId(0),
      cachedBitmap(0) {}

// SYNTHETIC: IMPERIALISM 0x0048f050
// TPicture::`scalar deleting destructor'

// Real destructor body (listing at 0x48f250, symbols.csv name
// "DestructCityDialogSharedBaseState" — a provisional Ghidra label, not a real class;
// hundreds of scalar deleting destructors across every TPicture-derived class call this
// one shared address). Releases the glyph/animation slot cached in glyphBase84 and
// resets the bitmap fields; cachedBitmap is only zeroed here, not deleted —
// its lifetime is owned by the picture-resource cache, not per-instance.
// FUNCTION: IMPERIALISM 0x0048f250
TPicture::~TPicture() {
  if (glyphBase84 != -1) {
    g_pModuleLibraryCacheState->ReleaseRecordById(glyphBase84);
  }
  glyphBase84 = -1;
  bitmapId = 0;
  resourceNamespaceId = 0;
  cachedBitmap = 0;
}

// FUNCTION: IMPERIALISM 0x0048f330
void TPicture::InitializePictureEntryBaseAndRefresh(TView* panel, int* offsetLayout,
                                                    int* sizeLayout, int layoutParam4,
                                                    int layoutParam5, short pictureId) {
  (void)layoutParam4;
  (void)layoutParam5;
  if (panel != 0) {
    nativeWindow50 = panel->nativeWindow50;
  }
  controlTag = 0x20202020; // '    '
  field04 = 1;
  field08 = 1;
  linkedChildHandler = panel;
  ownerLocalX = offsetLayout[0];
  ownerLocalY = offsetLayout[1];
  frameWidth34 = sizeLayout[0];
  frameHeight38 = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, 0);
  }
  resourceContext = 0;
  SetPictureResourceIdAndRefresh(pictureId, 0);
}

// Slot 0x44 override: draw the cached bitmap. 8bpp uncompressed pictures software-blit
// straight into the active QuickDraw surface; anything else realizes the default DIB
// palette and StretchDIBits-es to the active DC at the control's cached position.

// FUNCTION: IMPERIALISM 0x0048f3c0
void TPicture::Draw(RECT* rectBuffer) {
  if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
    CRect bounds;
    this->GetQDExtent(&bounds);
  }

  if (GetActiveQuickDrawSurfaceDib() != 0 &&
      this->cachedBitmap->m_pInfoHeader->bmiHeader.biBitCount == 8 &&
      this->cachedBitmap->m_pInfoHeader->bmiHeader.biCompression == 0) {
    CRect bounds;
    this->GetQDExtent(&bounds);
    int width = bounds.right - bounds.left;
    int height = bounds.bottom - bounds.top;
    CDib* surface = GetActiveQuickDrawSurfaceDib();
    this->cachedBitmap->BlitSurfaceRectSkippingTransparentColor(surface, 0, 0, width, height,
                                                                bounds.left, bounds.top, -1);
    return;
  }

  g_pModuleLibraryCacheState->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(
      GetActiveQuickDrawDc(), 0);

  int srcHeight = this->cachedBitmap->m_pInfoHeader->bmiHeader.biHeight;
  if (srcHeight <= 0) {
    srcHeight = -srcHeight;
  }
  {
    CPoint posForX;
    CPoint posForY;
    this->cachedBitmap->StretchDibitsRectToDc(
        GetActiveQuickDrawDc(), this->GetAbsolutePosition(&posForX)->x,
        this->GetAbsolutePosition(&posForY)->y, this->frameWidth34, this->frameHeight38, 0, 0,
        this->cachedBitmap->m_pInfoHeader->bmiHeader.biWidth, srcHeight);
  }
}

// Slot 0x08 override: allocate via slot 0x09 then copy city-dialog and picture-resource tail.

// FUNCTION: IMPERIALISM 0x0048f520
void TPicture::ResetPictureResourceEntry() {
  if (this->glyphBase84 != -1) {
    g_pModuleLibraryCacheState->ReleaseRecordById(this->glyphBase84);
  }
  this->glyphBase84 = -1;
  this->bitmapId = 0;
  this->resourceNamespaceId = 0;
  this->cachedBitmap = 0;
}

// FUNCTION: IMPERIALISM 0x0048f570
void TPicture::SetPictureResourceIdAndRefresh(short nPictureId, unsigned char fRefreshNow) {
  this->ResetPictureResourceEntry();
  this->glyphBase84 = nPictureId;
  if (nPictureId != -1) {
    this->cachedBitmap = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(nPictureId);
  }
  if (this->cachedBitmap == 0) {
    PictureFallbackSizeScratch sizeScratch;
    sizeScratch.Set(this->frameWidth34, this->frameHeight38);
    this->cachedBitmap = g_pModuleLibraryCacheState->BuildIndexedBmpResourceById(
        nPictureId, this->frameWidth34, this->frameHeight38, 0);
  }
  if (fRefreshNow) {
    this->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0048f610
void PictureFallbackSizeScratch::Set(int newWidth, int newHeight) {
  width = newWidth;
  height = newHeight;
}

// FUNCTION: IMPERIALISM 0x0048f640
TObject* TPicture::ShallowClone() {
  TPicture* clone = static_cast<TPicture*>(ShallowFree());
  clone->CopyViewStateFromSource(this);
  clone->eventNumber60 = eventNumber60;
  clone->controlState64 = controlState64;
  clone->contentInsets68 = contentInsets68;
  clone->textStyle78 = textStyle78;
  clone->glyphBase84 = glyphBase84;
  clone->reserved86 = reserved86;
  clone->bitmapId = bitmapId;
  clone->resourceNamespaceId = resourceNamespaceId;
  clone->cachedBitmap = cachedBitmap;
  if (glyphBase84 != static_cast<short>(0xffff)) {
    unsigned int packedId =
        (static_cast<unsigned int>(static_cast<unsigned short>(resourceNamespaceId)) << 16) |
        static_cast<unsigned int>(static_cast<unsigned short>(glyphBase84));
    g_pModuleLibraryCacheState->IncrementDialogResourceRefCountByShortIdInRegistry(packedId);
  }
  return clone;
}
