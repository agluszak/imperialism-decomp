#include "game/navy/TMilitaryPageView.h"
#include "game/ui_tags_common.h"

#include "game/core/CString.h"
#include "game/app/TAnimation.h"
#include "game/ui_screens/TBook.h"
#include "game/ui_core/TBitmapResourceLoader.h"
#include "game/map_ui/TMapDialog.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x00564860
// TMilitaryPageView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00564900
// TMilitaryPageView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMilitaryPageView, TPageView)

// SYNTHETIC: IMPERIALISM 0x00564950
// TMilitaryPageView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00564980
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

// Listing 0x00564a60 inlines the loader's exact-type non-virtual destructor.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x00564a60
void TMilitaryPageView::PrepareUnitCache(int bitmapResourceId, int width, int height) {
  (void)width;
  TMapDialog* mapDialog = g_pViewMgr->mapUberPictureF0->subview2A8;
  primaryUnitAtlas84 = mapDialog->quickDrawSurface350;
  mapDialog->suppressMarkerOverlay34C = true;
  mapDialog->ResetAllTileMarkersToSentinel();

  TBitmapResourceLoader** loaderHandle =
      CreateBitmapResourceLoaderHandle(static_cast<unsigned short>(bitmapResourceId));
  RECT destination = {0, 0, height, height};

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
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

// FUNCTION: IMPERIALISM 0x00564bf0
void TMilitaryPageView::Close() {
  TView::Close();
  TMapDialog* mapDialog = g_pViewMgr->mapUberPictureF0->subview2A8;
  mapDialog->suppressMarkerOverlay34C = false;
  mapDialog->ResetAllTileMarkersToSentinel();
}
