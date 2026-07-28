#include "RuntimeObservations.h"

#include "RuntimeJson.h"
#include "RuntimeRun.h"

#include "game/core/global_data_tables.h"
#include "game/gfx/CDib.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/globals/gfx_globals.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/map/TMapUberPicture.h"
#include "game/map/TMiniMapView.h"
#include "game/map/TMapMgr.h"
#include "game/map_ui/TMapDialog.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"

#include <string.h>

TView* RuntimeMainView() {
  if (g_pDisplayMgr == 0 || g_pDisplayMgr->activeDialog == 0) {
    return 0;
  }
  return g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagMain);
}

const char* RuntimeClassName(TView* view) {
  if (view == 0) {
    return "";
  }
  CRuntimeClass* runtimeClass = view->GetRuntimeClass();
  if (runtimeClass == 0 || runtimeClass->m_lpszClassName == 0) {
    return "";
  }
  return runtimeClass->m_lpszClassName;
}

bool RuntimeIsViewKindOf(TView* view, CRuntimeClass* runtimeClass) {
  return view != 0 && view->IsKindOf(runtimeClass) != 0;
}

namespace {

void CopySurfaceTile(unsigned char* destination, const unsigned char* source, int stride) {
  for (int row = 0; row < 0x40; ++row) {
    memcpy(destination + row * 0x40, source + row * stride, 0x40);
  }
}

void FourCcText(unsigned int tag, char text[5]) {
  text[0] = static_cast<char>(tag >> 24);
  text[1] = static_cast<char>(tag >> 16);
  text[2] = static_cast<char>(tag >> 8);
  text[3] = static_cast<char>(tag);
  text[4] = 0;
}

int TagOccurrenceBefore(TView* parent, TView* target) {
  if (parent == 0 || parent->childList44 == 0) {
    return 1;
  }
  int occurrence = 1;
  POSITION position = parent->childList44->GetHeadPosition();
  while (position != 0) {
    TView* sibling = parent->childList44->GetNext(position);
    if (sibling == target) {
      break;
    }
    if (sibling->controlTag == target->controlTag) {
      ++occurrence;
    }
  }
  return occurrence;
}

CString ViewPath(TView* view, const CString& parentPath) {
  CString path;
  path.Format("%08x#%d", static_cast<unsigned int>(view->controlTag),
              TagOccurrenceBefore(view->ownerContext, view));
  if (!parentPath.IsEmpty()) {
    path = parentPath + "/" + path;
  }
  return path;
}

void AppendViewTreeNodes(CString& json, TView* view, const CString& parentPath, bool& firstNode) {
  if (view == 0) {
    return;
  }
  CString path = ViewPath(view, parentPath);
  char tag[5];
  FourCcText(static_cast<unsigned int>(view->controlTag), tag);
  if (!firstNode) {
    json += ",\n";
  }
  firstNode = false;
  json += "      {\"path\": ";
  RuntimeJson::AppendString(json, path);
  json += ", \"parent\": ";
  if (parentPath.IsEmpty()) {
    json += "null";
  } else {
    RuntimeJson::AppendString(json, parentPath);
  }
  json += ", \"tag\": ";
  RuntimeJson::AppendString(json, tag);
  json += ", \"class\": ";
  RuntimeJson::AppendString(json, RuntimeClassName(view));
  CString fields;
  fields.Format(", \"bounds\": [%d, %d, %d, %d], \"absolute\": [%d, %d], \"state\": %d, "
                "\"enabled\": %d, \"control_value\": %d",
                view->ownerLocalX, view->ownerLocalY, view->frameWidth34, view->frameHeight38,
                view->absoluteX, view->absoluteY, view->enabled, view->viewEnabled,
                view->controlValue3c);
  json += fields;
  if (view->IsKindOf(RUNTIME_CLASS(TPicture)) != 0) {
    TPicture* picture = static_cast<TPicture*>(view);
    fields.Format(", \"picture_id\": %d", static_cast<int>(picture->glyphBase84));
    json += fields;
  }
  if (view->IsKindOf(RUNTIME_CLASS(TStaticText)) != 0) {
    TStaticText* text = static_cast<TStaticText*>(view);
    json += ", \"text\": ";
    RuntimeJson::AppendString(json, text->text != 0 ? static_cast<LPCSTR>(*text->text) : "");
  }
  json += "}";

  if (view->childList44 == 0) {
    return;
  }
  POSITION position = view->childList44->GetHeadPosition();
  while (position != 0) {
    TView* child = view->childList44->GetNext(position);
    AppendViewTreeNodes(json, child, path, firstNode);
  }
}

} // namespace

bool VerifyRuntimeStrategicCoastCornerComposite(TMapDialog* mapDialog) {
  if (mapDialog == 0 || mapDialog->quickDrawSurface350 == 0 || g_pMacViewMgr == 0 ||
      g_pMacViewMgr->atlas668 == 0) {
    return false;
  }
  short coastTile = -1;
  for (short tile = 0; tile < 0x1950 && coastTile == -1; ++tile) {
    const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
    if (terrain.GetTerrainKind() != kStrategicTerrainWater || terrain.adjacencyMaskB0b == 0 ||
        tile % 108 == 0 || tile % 108 == 107) {
      continue;
    }
    for (int corner = 0; corner < 6; ++corner) {
      int previousDirection = (corner + 5) % 6;
      int cornerBits = (1 << previousDirection) | (1 << corner);
      if ((terrain.adjacencyMaskB0b & cornerBits) != 0 &&
          g_pGlobalMapState->MapImprovementOffsetFromAdjacencyVariant(
              static_cast<char>(terrain.adjacencyMaskB0b), static_cast<char>(corner + 1),
              static_cast<char>(terrain.spriteVariantIndex01 & (1 << corner))) != 0) {
        coastTile = tile;
        break;
      }
    }
  }
  if (coastTile == -1) {
    return false;
  }

  TBitmapSurfaceNode** destinationHandle = GetGWorldPixMap(mapDialog->quickDrawSurface350);
  TBitmapSurfaceNode** sourceHandle = GetGWorldPixMap(g_pMacViewMgr->atlas668);
  if (destinationHandle == 0 || *destinationHandle == 0 || sourceHandle == 0 ||
      *sourceHandle == 0 || !LockPixels(destinationHandle)) {
    return false;
  }
  if (!LockPixels(sourceHandle)) {
    UnlockPixels(destinationHandle);
    return false;
  }
  TBitmapSurfaceNode* destinationSurface = *destinationHandle;
  TBitmapSurfaceNode* sourceSurface = *sourceHandle;
  int destinationStride = destinationSurface->stride & 0x3fff;
  int sourceStride = sourceSurface->stride & 0x3fff;
  unsigned char expected[0x1000];
  unsigned char actual[0x1000];
  TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[coastTile];
  TTerrainStateRecordView savedTerrain = terrain;
  short sourceOffset = g_pGlobalMapState->LookupTileSpriteVariantOffsetByAdjacencyMaskB(coastTile);
  CopySurfaceTile(expected, sourceSurface->pixelBits + sourceOffset, sourceStride);

  for (int corner = 0; corner < 6; ++corner) {
    int previousDirection = (corner + 5) % 6;
    int cornerBits = (1 << previousDirection) | (1 << corner);
    if ((terrain.adjacencyMaskB0b & cornerBits) == 0) {
      continue;
    }
    int coastOffset = g_pGlobalMapState->MapImprovementOffsetFromAdjacencyVariant(
        static_cast<char>(terrain.adjacencyMaskB0b), static_cast<char>(corner + 1),
        static_cast<char>(terrain.spriteVariantIndex01 & (1 << corner)));
    if (coastOffset == 0) {
      continue;
    }
    unsigned char* coastSource = sourceSurface->pixelBits + coastOffset;
    switch (corner) {
    case 0:
      mapDialog->CopyCoastCornerMaskBetweenDirections5And0(coastSource, expected, sourceStride,
                                                           0x40);
      break;
    case 1:
      mapDialog->CopyCoastCornerMaskBetweenDirections0And1(coastSource, expected, sourceStride,
                                                           0x40);
      break;
    case 2:
      mapDialog->CopyCoastCornerMaskBetweenDirections1And2(coastSource, expected, sourceStride,
                                                           0x40);
      break;
    case 3:
      mapDialog->CopyCoastCornerMaskBetweenDirections2And3(coastSource, expected, sourceStride,
                                                           0x40);
      break;
    case 4:
      mapDialog->CopyCoastCornerMaskBetweenDirections3And4(coastSource, expected, sourceStride,
                                                           0x40);
      break;
    case 5:
      mapDialog->CopyCoastCornerMaskBetweenDirections4And5(coastSource, expected, sourceStride,
                                                           0x40);
      break;
    }
  }

  terrain.riverSpriteCode = kRiverSpriteCodeNone;
  terrain.ownerBorderMask07 = 0;
  terrain.cityBorderMask08 = 0;
  terrain.adjacencyBits06 = 0;
  terrain.railFlags17 = 0;
  terrain.activeFlags1c = 0;
  terrain.resourceTypeByEdge[0] = -1;
  terrain.resourceTypeByEdge[1] = -1;
  terrain.secondaryOwnerNationTag18 = -1;
  terrain.perTileVisitedFlag0f = 0;
  terrain.tileActionState16 = static_cast<MapTileActionStateStorage>(-1);
  TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
  short savedCategory = mapView->activeUnitCategoryIndex96;
  short savedRiverMouth = g_pGlobalMapState->pendingRiverMouthTile;
  mapView->activeUnitCategoryIndex96 = 4;
  g_pGlobalMapState->pendingRiverMouthTile = -1;
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(mapDialog->quickDrawSurface350, savedSurfaceFlags);
  mapDialog->DrawOneTile(coastTile, 0, 0);
  CopySurfaceTile(actual, destinationSurface->pixelBits, destinationStride);
  terrain = savedTerrain;
  mapView->activeUnitCategoryIndex96 = savedCategory;
  g_pGlobalMapState->pendingRiverMouthTile = savedRiverMouth;
  mapDialog->DrawOneTile(coastTile, 0, 0);
  SetGWorld(savedSurface, savedSurfaceFlags);
  UnlockPixels(sourceHandle);
  UnlockPixels(destinationHandle);
  return memcmp(expected, actual, sizeof(expected)) == 0;
}

bool VerifyRuntimeMiniMapViewportFrame(TMiniMapView* miniMap) {
  if (miniMap == 0 || miniMap->markerBoxWidth98 != 9 || miniMap->markerBoxHeight9c != 8 ||
      g_pPrimaryRenderSurfaceContext == 0) {
    return false;
  }
  TQuickDrawBlitSurface* surface = g_pPrimaryRenderSurfaceContext->GetBlitSurface();
  int surfaceWidth = surface->stride;
  int surfaceHeight = surface->clipRect.bottom - surface->clipRect.top;
  if (surface->pixelBits == 0 || surfaceWidth <= 0 || surfaceHeight <= 0) {
    return false;
  }
  int surfaceBytes = surfaceWidth * surfaceHeight;
  unsigned char* framed = new unsigned char[surfaceBytes];
  unsigned char* shiftedFrame = new unsigned char[surfaceBytes];
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
  miniMap->PrepareForDrawing();
  miniMap->Draw(0);
  GdiFlush();
  memcpy(framed, surface->pixelBits, surfaceBytes);
  int savedMarkerX = miniMap->markerBoxX90;
  int savedMarkerY = miniMap->markerBoxY94;
  miniMap->markerBoxX90 = savedMarkerX + 2;
  miniMap->markerBoxY94 = savedMarkerY + 2;
  miniMap->PrepareForDrawing();
  miniMap->Draw(0);
  GdiFlush();
  memcpy(shiftedFrame, surface->pixelBits, surfaceBytes);
  miniMap->markerBoxX90 = savedMarkerX;
  miniMap->markerBoxY94 = savedMarkerY;
  miniMap->PrepareForDrawing();
  miniMap->Draw(0);
  GdiFlush();
  SetGWorld(savedSurface, savedSurfaceFlags);
  bool differs = memcmp(framed, shiftedFrame, surfaceBytes) != 0;
  delete[] shiftedFrame;
  delete[] framed;
  return differs;
}

bool CaptureRuntimePrimarySurfaceBmp(const char* resultPath) {
  if (g_pPrimaryRenderSurfaceContext == 0) {
    return false;
  }
  TQuickDrawBlitSurface* surface = g_pPrimaryRenderSurfaceContext->GetBlitSurface();
  CDib* dib = surface->surfaceDib;
  if (dib == 0 || dib->m_pInfoHeader == 0 || surface->pixelBits == 0) {
    return false;
  }
  char screenshotPath[MAX_PATH];
  lstrcpynA(screenshotPath, resultPath, sizeof(screenshotPath));
  char* extension = strrchr(screenshotPath, '.');
  if (extension == 0) {
    extension = screenshotPath + lstrlenA(screenshotPath);
  }
  lstrcpyA(extension, ".bmp");
  CFile file;
  CFileException error;
  if (!file.Open(screenshotPath, CFile::modeCreate | CFile::modeWrite | CFile::shareDenyNone,
                 &error)) {
    return false;
  }
  int height = dib->GetAbsoluteHeight();
  int pixelBytes = surface->stride * height;
  int infoBytes = sizeof(BITMAPINFOHEADER) + dib->m_paletteCount * sizeof(RGBQUAD);
  BITMAPFILEHEADER fileHeader;
  fileHeader.bfType = 0x4d42;
  fileHeader.bfReserved1 = 0;
  fileHeader.bfReserved2 = 0;
  fileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + infoBytes;
  fileHeader.bfSize = fileHeader.bfOffBits + pixelBytes;
  file.Write(&fileHeader, sizeof(fileHeader));
  file.Write(dib->m_pInfoHeader, infoBytes);
  file.Write(surface->pixelBits, pixelBytes);
  file.Close();
  return true;
}

bool CaptureRuntimeWindowBmp(const char* resultPath, HWND window, int width, int height) {
  if (window == 0 || width <= 0 || height <= 0) {
    return false;
  }
  HDC sourceDc = GetDC(window);
  HDC captureDc = CreateCompatibleDC(sourceDc);
  BITMAPINFO info;
  memset(&info, 0, sizeof(info));
  info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  info.bmiHeader.biWidth = width;
  info.bmiHeader.biHeight = -height;
  info.bmiHeader.biPlanes = 1;
  info.bmiHeader.biBitCount = 32;
  info.bmiHeader.biCompression = BI_RGB;
  info.bmiHeader.biSizeImage = width * height * 4;
  void* pixels = 0;
  HBITMAP bitmap = CreateDIBSection(sourceDc, &info, DIB_RGB_COLORS, &pixels, 0, 0);
  HGDIOBJ savedBitmap = SelectObject(captureDc, bitmap);
  BOOL copied = BitBlt(captureDc, 0, 0, width, height, sourceDc, 0, 0, SRCCOPY);
  GdiFlush();
  char screenshotPath[MAX_PATH];
  lstrcpynA(screenshotPath, resultPath, sizeof(screenshotPath));
  char* extension = strrchr(screenshotPath, '.');
  if (extension == 0) {
    extension = screenshotPath + lstrlenA(screenshotPath);
  }
  lstrcpyA(extension, "-window.bmp");
  CFile file;
  CFileException error;
  bool wrote = false;
  if (copied && pixels != 0 &&
      file.Open(screenshotPath, CFile::modeCreate | CFile::modeWrite | CFile::shareDenyNone,
                &error)) {
    BITMAPFILEHEADER fileHeader;
    fileHeader.bfType = 0x4d42;
    fileHeader.bfReserved1 = 0;
    fileHeader.bfReserved2 = 0;
    fileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    fileHeader.bfSize = fileHeader.bfOffBits + info.bmiHeader.biSizeImage;
    file.Write(&fileHeader, sizeof(fileHeader));
    file.Write(&info.bmiHeader, sizeof(info.bmiHeader));
    file.Write(pixels, info.bmiHeader.biSizeImage);
    file.Close();
    wrote = true;
  }
  SelectObject(captureDc, savedBitmap);
  DeleteObject(bitmap);
  DeleteDC(captureDc);
  ReleaseDC(window, sourceDc);
  return wrote;
}

CString CaptureRuntimeUiSnapshot(int eventCode, TView* root) {
  CString json;
  CString header;
  header.Format("    {\"event\": %d, \"nodes\": [\n", eventCode);
  json += header;
  bool firstNode = true;
  AppendViewTreeNodes(json, root, CString(), firstNode);
  json += "\n    ]}";
  return json;
}

void CaptureRuntimeMapState(RuntimeRun& run) {
  if (g_pGlobalMapState == 0 || !run.MapStateJson().IsEmpty()) {
    return;
  }
  long terrainCounts[kStrategicTerrainCount + 1];
  long ownedTiles[7];
  memset(terrainCounts, 0, sizeof(terrainCounts));
  memset(ownedTiles, 0, sizeof(ownedTiles));
  for (short tile = 0; tile < 0x1950; ++tile) {
    const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
    int kind = static_cast<int>(terrain.GetTerrainKind());
    if (kind < 0 || kind >= kStrategicTerrainCount) {
      kind = kStrategicTerrainCount;
    }
    ++terrainCounts[kind];
    short owner = terrain.ownerNationTag04;
    if (owner >= 0 && owner < 7) {
      ++ownedTiles[owner];
    }
  }
  CString terrainJson("[");
  CString item;
  for (int kindIndex = 0; kindIndex <= kStrategicTerrainCount; ++kindIndex) {
    item.Format("%s%ld", kindIndex == 0 ? "" : ", ", terrainCounts[kindIndex]);
    terrainJson += item;
  }
  terrainJson += "]";
  CString ownedJson("[");
  for (int nationSlot = 0; nationSlot < 7; ++nationSlot) {
    item.Format("%s%ld", nationSlot == 0 ? "" : ", ", ownedTiles[nationSlot]);
    ownedJson += item;
  }
  ownedJson += "]";
  run.MapStateJson().Format(
      "{\"terrain_counts\": %s, \"owned_tiles\": %s, \"wrap\": %d, "
      "\"representative_tile\": %d, \"economic_turn\": %d}",
      static_cast<LPCSTR>(terrainJson), static_cast<LPCSTR>(ownedJson),
      g_pGlobalMapState->hexNeighborWrapHorizontally,
      g_pGlobalMapState->ComputeRepresentativeTileIndexForNation(run.SelectedNationSlot()),
      g_pSimMgr != 0 ? static_cast<int>(g_pSimMgr->economicTurn) : -1);
}
