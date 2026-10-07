#include "game/ui_core/TPicture.h"
#include "game/ui_tags_common.h"

#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"
#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "game/ui_core/TView.h"
#include "game/gfx/TResourceMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

struct PictureFallbackSizeScratch {
  int width;
  int height;

  void Set(int newWidth, int newHeight);
};

IMPLEMENT_DYNCREATE(TPicture, TControl)

// FUNCTION: IMPERIALISM 0x0048efc0
TPicture::TPicture()
    : TControl(), glyphBase(-1), reserved86(0), bitmapId(0), resourceNamespaceId(0),
      cachedBitmap(0) {}

// FUNCTION: IMPERIALISM 0x0048f080
TPicture::TPicture(const TPicture& source)
    : TControl(source), glyphBase(source.glyphBase), bitmapId(source.bitmapId),
      resourceNamespaceId(source.resourceNamespaceId), cachedBitmap(source.cachedBitmap) {
  if (glyphBase != -1) {
    g_pResourceMgr->IncrementRecordRefCountById(glyphBase);
  }
}

// FUNCTION: IMPERIALISM 0x0048f190
void TPicture::CopyPictureStateFromSource(TPicture* source) {
  // Takes a pointer, matching TView::CopyViewStateFromSource which it forwards to.
  CopyViewStateFromSource(source);
  eventNumber = source->eventNumber;
  controlState = source->controlState;
  contentInsets = source->contentInsets;
  textStyle = source->textStyle;
  glyphBase = source->glyphBase;
  bitmapId = source->bitmapId;
  resourceNamespaceId = source->resourceNamespaceId;
  cachedBitmap = source->cachedBitmap;
  if (glyphBase != -1) {
    g_pResourceMgr->IncrementRecordRefCountById(glyphBase);
  }
}

// FUNCTION: IMPERIALISM 0x0048f250
TPicture::~TPicture() {
  if (glyphBase != -1) {
    g_pResourceMgr->ReleaseRecordById(glyphBase);
  }
  glyphBase = -1;
  bitmapId = 0;
  resourceNamespaceId = 0;
  cachedBitmap = 0;
}

// FUNCTION: IMPERIALISM 0x0048f330
void TPicture::IPicture(TView* panel, int* offsetLayout, int* sizeLayout, int layoutParam4,
                        int layoutParam5, short pictureId) {
  if (panel != 0) {
    nativeWindow = panel->nativeWindow;
  }
  controlTag = kControlTagSpSpSpSp; // '    '
  enabled = 1;
  viewEnabled = 1;
  nextHandler = panel;
  ownerLocalX = offsetLayout[0];
  ownerLocalY = offsetLayout[1];
  frameWidth = sizeLayout[0];
  frameHeight = sizeLayout[1];
  if (panel != 0) {
    panel->AttachChildControl(this, 0);
  }
  resourceContext = 0;
  SetPictureRsrcID(pictureId, 0);
}

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

  g_pResourceMgr->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(GetActiveQuickDrawDc(), 0);

  int srcHeight = this->cachedBitmap->m_pInfoHeader->bmiHeader.biHeight;
  if (srcHeight <= 0) {
    srcHeight = -srcHeight;
  }
  {
    CPoint posForX;
    CPoint posForY;
    this->cachedBitmap->StretchDibitsRectToDc(
        GetActiveQuickDrawDc(), this->GetAbsolutePosition(&posForX)->x,
        this->GetAbsolutePosition(&posForY)->y, this->frameWidth, this->frameHeight, 0, 0,
        this->cachedBitmap->m_pInfoHeader->bmiHeader.biWidth, srcHeight);
  }
}

// FUNCTION: IMPERIALISM 0x0048f520
void TPicture::ReleasePicture() {
  if (this->glyphBase != -1) {
    g_pResourceMgr->ReleaseRecordById(this->glyphBase);
  }
  this->glyphBase = -1;
  this->bitmapId = 0;
  this->resourceNamespaceId = 0;
  this->cachedBitmap = 0;
}

// FUNCTION: IMPERIALISM 0x0048f570
void TPicture::SetPictureRsrcID(short nPictureId, unsigned char fRefreshNow) {
  this->ReleasePicture();
  this->glyphBase = nPictureId;
  if (nPictureId != -1) {
    this->cachedBitmap = g_pResourceMgr->LoadBmpResourceByIdCached(nPictureId);
  }
  if (this->cachedBitmap == 0) {
    PictureFallbackSizeScratch sizeScratch;
    sizeScratch.Set(this->frameWidth, this->frameHeight);
    this->cachedBitmap = g_pResourceMgr->BuildIndexedBmpResourceById(nPictureId, this->frameWidth,
                                                                     this->frameHeight, 0);
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
  clone->eventNumber = eventNumber;
  clone->controlState = controlState;
  clone->contentInsets = contentInsets;
  clone->textStyle = textStyle;
  clone->glyphBase = glyphBase;
  clone->bitmapId = bitmapId;
  clone->resourceNamespaceId = resourceNamespaceId;
  clone->cachedBitmap = cachedBitmap;
  if (glyphBase != -1) {
    g_pResourceMgr->IncrementRecordRefCountById(glyphBase);
  }
  return clone;
}
