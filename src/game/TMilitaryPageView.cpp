#include "game/TMilitaryPageView.h"

#include "game/CString.h"
#include "game/TAnimation.h"
#include "game/TBook.h"
#include "game/TBitmapResourceLoader.h"
#include "game/TMapDialog.h"
#include "game/TMapUberPicture.h"
#include "game/TViewMgr.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x00564860
// TMilitaryPageView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00564900
// TMilitaryPageView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMilitaryPageView, TPageView)

// FUNCTION: IMPERIALISM 0x00564920
TMilitaryPageView::TMilitaryPageView() : TPageView(), primaryUnitAtlas84(0) {}

// SYNTHETIC: IMPERIALISM 0x00564950
// TMilitaryPageView::`scalar deleting destructor'
TMilitaryPageView::~TMilitaryPageView() {}

// FUNCTION: IMPERIALISM 0x005649a0
void TMilitaryPageView::DoPostCreate(int arg) {
  TPageView::DoPostCreate(arg);
  TView* okControl = ownerContext->ResolveControlByTag(kControlTagOkay);
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 0x22, okControl);
  CString empty(g_szEmptyString);
  SetControlHoverHelpText(empty, this);
}

// FUNCTION: IMPERIALISM 0x00564a10
void TMilitaryPageView::AfterStuffValues() {
  visibleColumnCount = 2;
  BuildPageLayout();
  ShowPage(1);

  TBook* book = static_cast<TBook*>(ownerContext);
  book->AssertValid();
  book->ShowPage(currentPage);
}

// FUNCTION: IMPERIALISM 0x00564a60
void TMilitaryPageView::PrepareUnitCache(int bitmapResourceId, int width, int height) {
  TMapDialog* mapDialog = g_pUiRuntimeContext->mapUberPictureF0->subview2A8;
  primaryUnitAtlas84 = mapDialog->quickDrawSurface350;
  mapDialog->suppressMarkerOverlay34C = true;
  mapDialog->ResetAllTileMarkersToSentinel();

  TBitmapResourceLoader** loaderHandle =
      CreateBitmapResourceLoaderHandle(static_cast<unsigned short>(bitmapResourceId));
  RECT destination = {0, 0, width, height};

  TQuickDrawSurfaceContext* savedContext;
  int savedFlags;
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(primaryUnitAtlas84, savedFlags);
  LockPixels(GetGWorldPixMap(primaryUnitAtlas84));
  QDLoadResource(loaderHandle);

  TBitmapResourceLoader* loader = *loaderHandle;
  if (loader != 0) {
    unsigned char previousLoaderFlags = loader->flags;
    loader->EnsureBitmapResourceLoadedAndCopyRectSize();
    loader->flags |= 1;
    ResetQuickDrawStrokeState();
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, &destination);
    unsigned char currentLoaderFlags = loader->flags;
    loader->flags = previousLoaderFlags;
    if (currentLoaderFlags != 0 && previousLoaderFlags == 0) {
      loader->ReleaseBitmapResource();
      loader->flags &= 0xfe;
    }
  }

  loader = *loaderHandle;
  loader->ReleaseBitmapResource();
  loader->flags &= 0xfe;
  delete loader;
  delete loaderHandle;

  SetGWorld(savedContext, savedFlags);
}

// FUNCTION: IMPERIALISM 0x00564bf0
void TMilitaryPageView::Close() {
  TView::Close();
  TMapDialog* mapDialog = g_pUiRuntimeContext->mapUberPictureF0->subview2A8;
  mapDialog->suppressMarkerOverlay34C = false;
  mapDialog->ResetAllTileMarkersToSentinel();
}
