#include "game/TMapPreviewView.h"
#include "game/TDisplayMgr.h"
#include "game/TMacViewMgr.h"
#include "game/TMapMgr.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

#include "game/bitmap_descriptor_helpers.h"
#include "game/quickdraw_rendering.h"

#include <string.h>

// SYNTHETIC: IMPERIALISM 0x0043d5c0
// TMapPreviewView::`scalar deleting destructor'
TMapPreviewView::~TMapPreviewView() {}
// SYNTHETIC: IMPERIALISM 0x005787b0
// TMapPreviewView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00578830
// TMapPreviewView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapPreviewView, TView)

// FUNCTION: IMPERIALISM 0x0043d590
TMapPreviewView::TMapPreviewView() : TView() {
  selectedRegion64 = -1;
}

// FUNCTION: IMPERIALISM 0x00578850
void TMapPreviewView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  selectedNation68 = -1;
  field04 = 1;

  CRect contentBounds;
  QueryContentBounds(&contentBounds);
  RECT surfaceBounds = contentBounds;

  ++g_nDibOrientationFlag_006A1890;
  g_pDisplayMgr->MakeNewGWorld(previewSurface60, 8, surfaceBounds);

  TBitmapSurfaceNode** surfaceObject = GetGWorldPixMap(previewSurface60);
  unsigned char* pixels = GetPixBaseAddr(surfaceObject);
  int stride = static_cast<unsigned short>((*surfaceObject)->stride) & 0x3fff;
  int height = surfaceBounds.bottom - surfaceBounds.top;
  memset(pixels, 0x10, height * stride);
  --g_nDibOrientationFlag_006A1890;
}

// FUNCTION: IMPERIALISM 0x005789b0
void TMapPreviewView::Free() {
  g_pDisplayMgr->RemoveGWorld(previewSurface60);
  TView::Free();
}

// FUNCTION: IMPERIALISM 0x005789e0
void TMapPreviewView::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  (void)event;
  (void)origin;

  TBitmapSurfaceNode** surfaceObject = GetGWorldPixMap(previewSurface60);
  unsigned char* pixels = GetPixBaseAddr(surfaceObject);
  int stride = static_cast<unsigned short>((*surfaceObject)->stride) & 0x3fff;
  unsigned short clickedPalette = pixels[point.y * stride + point.x];

  for (int nation = 0; nation < 7; ++nation) {
    unsigned short nationPalette =
        static_cast<unsigned short>(g_pUiRuntimeContext->GetColor(static_cast<short>(nation)));
    if (nationPalette == clickedPalette) {
      pendingNation6C = nation;
      ownerContext->DoEvent(0x7069636b /* 'pick' */, this, 0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00578a80
void TMapPreviewView::Draw(RECT* rectBuffer) {
  (void)rectBuffer;

  RECT previewRect = {0, 0, frameWidth34, frameHeight38};
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitQuickDrawSurfaces(previewSurface60->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &previewRect,
                        &previewRect, 0x24);

  if (selectedRegion64 != -1) {
    short columnX2;
    unsigned short row;
    short tileIndex = g_pGlobalMapState->cityScoreTable[selectedRegion64].cityTileIndex04;
    SplitTileIndexToHexRasterColumnX2AndRow(tileIndex, &columnX2, &row);

    RECT markerSource = {0x48, 0, 0x5a, 0x12};
    RECT markerDest;
    markerDest.left = (static_cast<int>(columnX2) * 3) / 2 - 9;
    markerDest.top = (static_cast<int>(row) - 3) * 3;
    markerDest.right = markerDest.left + 0x12;
    markerDest.bottom = markerDest.top + 0x12;
    BlitQuickDrawSurfaces(g_pStrategicMapViewSystem->atlas694[3]->GetBlitSurface(),
                          g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &markerSource,
                          &markerDest, 0x24);
  }

  SetQuickDrawStrokeColor(0xffffff);
}

namespace {

// Resolve a map owner tag to the palette byte stored in the preview surface. Minor
// nations share palette entry 0xb; -1 is off-map and -2 is a contested hex corner.
static __inline unsigned char ResolvePreviewMapOwnerTagPaletteByte(int ownerTag) {
  if (ownerTag >= 7 && ownerTag < 0x17) {
    ownerTag = 0xb;
  }
  if (ownerTag == -1) {
    return 0x10;
  }
  if (ownerTag == -2) {
    return 0;
  }
  return static_cast<unsigned char>(g_pUiRuntimeContext->GetColor(static_cast<short>(ownerTag)));
}

} // namespace

// FUNCTION: IMPERIALISM 0x00578c10
void TMapPreviewView::TakeSatellitePhoto(char* tileOwnerTagTable) {
  unsigned char* tileBuffer = GetPixBaseAddr(GetGWorldPixMap(previewSurface60));
  TBitmapSurfaceNode** surfaceObject = GetGWorldPixMap(previewSurface60);
  int strideBytes = static_cast<unsigned short>((*surfaceObject)->stride) & 0x3fff;

  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    short px;
    unsigned short py;
    short hexTags[7];
    SplitTileIndexToHexRasterColumnX2AndRow(static_cast<short>(tileIndex), &px, &py);
    unsigned char oddRow = static_cast<unsigned char>(py) & 1;
    py = static_cast<short>(py * 3);
    px = static_cast<short>((px * 3) / 2);
    TMapMgr::GetNeighborTileIDArray(static_cast<short>(tileIndex), hexTags, 1);
    hexTags[6] = static_cast<short>(tileIndex);

    if (tileOwnerTagTable != 0) {
      for (int i = 0; i < 7; ++i) {
        hexTags[i] = (hexTags[i] == -1) ? -1 : tileOwnerTagTable[hexTags[i]];
      }
    } else {
      for (int j = 0; j < 7; ++j) {
        hexTags[j] = (hexTags[j] == -1)
                         ? -1
                         : g_pGlobalMapState->terrainStateTable[hexTags[j]].ownerNationTag04;
      }
    }
    for (int k = 0; k < 7; ++k) {
      hexTags[k] = (hexTags[k] >= 0x17) ? -1 : hexTags[k];
    }

    int tag;
    if (hexTags[6] == hexTags[5]) {
      tag = hexTags[6];
    } else if ((oddRow != 0 && hexTags[5] == hexTags[4]) ||
               (oddRow == 0 && hexTags[5] == hexTags[0] && hexTags[4] == hexTags[0])) {
      tag = hexTags[5];
    } else {
      tag = -2;
    }
    tileBuffer[py * strideBytes + px] = ResolvePreviewMapOwnerTagPaletteByte(tag);

    if (oddRow != 0) {
      tag = (hexTags[6] == hexTags[5]) ? hexTags[6] : -2;
      tileBuffer[py * strideBytes + (px + 1)] = ResolvePreviewMapOwnerTagPaletteByte(tag);
      tag = (hexTags[6] == hexTags[0] || (hexTags[6] == hexTags[1] && hexTags[6] == hexTags[5]))
                ? hexTags[6]
                : -2;
      tileBuffer[py * strideBytes + (px + 2)] = ResolvePreviewMapOwnerTagPaletteByte(tag);
    } else {
      tag = (hexTags[6] == hexTags[0] || hexTags[6] == hexTags[5]) ? hexTags[6] : -2;
      tileBuffer[py * strideBytes + (px + 1)] = ResolvePreviewMapOwnerTagPaletteByte(tag);
      tag = (hexTags[6] == hexTags[0]) ? hexTags[6] : -2;
      tileBuffer[py * strideBytes + (px + 2)] = ResolvePreviewMapOwnerTagPaletteByte(tag);
    }

    tag = (hexTags[6] == hexTags[4]) ? hexTags[6] : -2;
    tileBuffer[(py + 1) * strideBytes + px] = ResolvePreviewMapOwnerTagPaletteByte(tag);
    tag = (hexTags[6] == hexTags[4]) ? hexTags[6] : -2;
    tileBuffer[(py + 2) * strideBytes + px] = ResolvePreviewMapOwnerTagPaletteByte(tag);
    tileBuffer[(py + 1) * strideBytes + (px + 1)] =
        ResolvePreviewMapOwnerTagPaletteByte(hexTags[6]);
    tileBuffer[(py + 2) * strideBytes + (px + 1)] =
        ResolvePreviewMapOwnerTagPaletteByte(hexTags[6]);
    tileBuffer[(py + 1) * strideBytes + (px + 2)] =
        ResolvePreviewMapOwnerTagPaletteByte(hexTags[6]);
    tileBuffer[(py + 2) * strideBytes + (px + 2)] =
        ResolvePreviewMapOwnerTagPaletteByte(hexTags[6]);
  }
}

// FUNCTION: IMPERIALISM 0x00579270
void TMapPreviewView::EnhancePhoto() {
  unsigned char maskColors[7];
  maskColors[0] = 2;
  maskColors[1] = 0xf;
  maskColors[2] = 2;
  maskColors[3] = 6;
  maskColors[4] = 0x20;
  maskColors[5] = 5;
  maskColors[6] = 0xca;

  unsigned char hasSelection = selectedNation68 != -1;
  unsigned char selectedPalette = 0;
  if (hasSelection != 0) {
    selectedPalette = static_cast<unsigned char>(
        g_pUiRuntimeContext->GetColor(static_cast<short>(selectedNation68)));
  }

  TBitmapSurfaceNode** surfaceObject = GetGWorldPixMap(previewSurface60);
  unsigned char* pixels = GetPixBaseAddr(surfaceObject);
  int stride = static_cast<unsigned short>((*surfaceObject)->stride) & 0x3fff;

  unsigned char* rowStart = pixels + stride + 1;
  for (int row = 0; row < 0xb2; ++row) {
    unsigned char* pixel = rowStart;
    for (int column = 0; column < 0x142; ++column, ++pixel) {
      unsigned char value = *pixel;
      unsigned char maskable = value == 0 || value == 0x13;
      for (int i = 0; i < 7 && maskable == 0; ++i) {
        if (value == maskColors[i]) {
          maskable = 1;
        }
      }
      if (maskable != 0) {
        if (hasSelection != 0 &&
            (pixel[-1] == selectedPalette || pixel[1] == selectedPalette ||
             pixel[-stride] == selectedPalette || pixel[stride] == selectedPalette)) {
          *pixel = 0x13;
        } else {
          *pixel = 0;
        }
      }
    }
    rowStart += stride;
  }
}
