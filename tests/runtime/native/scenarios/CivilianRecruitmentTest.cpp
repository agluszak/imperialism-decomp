#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"

#include "decomp_types.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/app/TAnimator.h"
#include "game/app/TCivAnimation2.h"
#include "game/city/TCity.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TCivMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/pointer_representation.h"
#include "game/strategic_terrain.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

bool CursorDrawsVisiblePixels(HCURSOR cursor) {
  BITMAPINFO bitmapInfo;
  ZeroMemory(&bitmapInfo, sizeof(bitmapInfo));
  bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bitmapInfo.bmiHeader.biWidth = 32;
  bitmapInfo.bmiHeader.biHeight = -32;
  bitmapInfo.bmiHeader.biPlanes = 1;
  bitmapInfo.bmiHeader.biBitCount = 32;
  bitmapInfo.bmiHeader.biCompression = BI_RGB;

  void* pixelStorage = 0;
  HDC screenDc = GetDC(0);
  HBITMAP bitmap = CreateDIBSection(screenDc, &bitmapInfo, DIB_RGB_COLORS, &pixelStorage, 0, 0);
  DWORD* pixels = static_cast<DWORD*>(pixelStorage);
  HDC memoryDc = CreateCompatibleDC(screenDc);
  HGDIOBJ previousBitmap = SelectObject(memoryDc, bitmap);
  PatBlt(memoryDc, 0, 0, 32, 32, WHITENESS);
  BOOL drewCursor = DrawIconEx(memoryDc, 0, 0, cursor, 32, 32, 0, 0, DI_NORMAL);

  bool changedPixel = false;
  if (drewCursor != 0) {
    for (int index = 0; index < 32 * 32; ++index) {
      if ((pixels[index] & 0x00ffffff) != 0x00ffffff) {
        changedPixel = true;
        break;
      }
    }
  }

  SelectObject(memoryDc, previousBitmap);
  DeleteDC(memoryDc);
  DeleteObject(bitmap);
  ReleaseDC(0, screenDc);
  return changedPixel;
}

bool CaptureViewPixels(TView* view, DWORD** outPixels, int* outWidth, int* outHeight) {
  if (view == 0 || view->nativeWindow50 == 0 || view->nativeWindow50->m_hWnd == 0 ||
      view->frameWidth34 <= 0 || view->frameHeight38 <= 0) {
    return false;
  }

  BITMAPINFO bitmapInfo;
  ZeroMemory(&bitmapInfo, sizeof(bitmapInfo));
  bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bitmapInfo.bmiHeader.biWidth = view->frameWidth34;
  bitmapInfo.bmiHeader.biHeight = -view->frameHeight38;
  bitmapInfo.bmiHeader.biPlanes = 1;
  bitmapInfo.bmiHeader.biBitCount = 32;
  bitmapInfo.bmiHeader.biCompression = BI_RGB;

  HDC windowDc = GetDC(view->nativeWindow50->m_hWnd);
  void* capturedStorage = 0;
  HBITMAP bitmap = CreateDIBSection(windowDc, &bitmapInfo, DIB_RGB_COLORS, &capturedStorage, 0, 0);
  HDC memoryDc = CreateCompatibleDC(windowDc);
  HGDIOBJ previousBitmap = SelectObject(memoryDc, bitmap);
  BOOL copied = BitBlt(memoryDc, 0, 0, view->frameWidth34, view->frameHeight38, windowDc,
                       view->absoluteX, view->absoluteY, SRCCOPY);
  GdiFlush();

  int pixelCount = view->frameWidth34 * view->frameHeight38;
  DWORD* pixels = 0;
  if (copied != 0 && capturedStorage != 0) {
    pixels = new DWORD[pixelCount];
    memcpy(pixels, capturedStorage, pixelCount * sizeof(DWORD));
  }

  SelectObject(memoryDc, previousBitmap);
  DeleteDC(memoryDc);
  DeleteObject(bitmap);
  ReleaseDC(view->nativeWindow50->m_hWnd, windowDc);
  if (pixels == 0) {
    return false;
  }
  *outPixels = pixels;
  *outWidth = view->frameWidth34;
  *outHeight = view->frameHeight38;
  return true;
}

class CivilianRecruitmentTestCase : public RandomGameScenario {
public:
  CivilianRecruitmentTestCase()
      : spawnedCivilian(0), targetHillTile(-1), targetSeaTile(-1), orderIssued(false),
        initialAnimationFrame(0), initialAnimationTick(0) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    spawnedCivilian = 0;
    orderIssued = false;
    EnterScenarioStep("recruiting_civilian", "produce_and_select_recruited_civilian");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (spawnedCivilian == 0) {
      RecruitCivilian();
      return;
    }

    if (!orderIssued) {
      VerifyProspectorOrdersAndCursors();
      return;
    }

    g_pUiAnimator->DoIdle(1);
    VerifyOrderedProspectorRemainsVisibleAndInspectable();
  }

private:
  enum { kGlobalMapTileCount = 0x1950 };

  void RecruitCivilian() {
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      WaitForScenarioTick("\"combined map was not idle before civilian recruitment\"");
      return;
    }

    short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0 || nation->trackedObjectList == 0) {
      FailScenario("\"active nation has no civilian recruitment state\"");
      return;
    }

    int oldCount = nation->trackedObjectList->GetCount();
    int oldPersistentUnitId = g_pSimMgr->field_64;
    TUnitOrder recruitOrder;
    recruitOrder.IUnitOrder(nation->city, EncodeCivilianUnitKind(kCivilianUnitProspector), 0, 0, -1,
                            0, 0, kLowSkillWorkforceMode, 0);
    recruitOrder.quantity = 1;
    recruitOrder.Produce();

    if (nation->trackedObjectList->GetCount() != oldCount + 1) {
      FailScenario("\"civilian production did not register exactly one recruit\"");
      return;
    }
    if (g_pSimMgr->field_64 != oldPersistentUnitId + 1) {
      FailScenario("\"civilian production did not allocate exactly one persistent unit ID\"");
      return;
    }
    spawnedCivilian = 0;
    for (int ordinal = 1; ordinal <= nation->trackedObjectList->GetCount(); ++ordinal) {
      CObject* entry = static_cast<CObject*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      if (entry != 0 && entry->IsKindOf(RUNTIME_CLASS(TCivUnit)) != 0) {
        TCivUnit* civilian = static_cast<TCivUnit*>(entry);
        if (civilian->persistentUnitId20 == g_pSimMgr->field_64) {
          spawnedCivilian = civilian;
          break;
        }
      }
    }
    if (spawnedCivilian == 0 || spawnedCivilian->tileIndex06 < 0 ||
        spawnedCivilian->tileIndex06 >= kGlobalMapTileCount) {
      FailScenario("\"newly allocated civilian has an invalid strategic-map tile\"");
      return;
    }

    signed char ownerTag =
        g_pGlobalMapState->terrainStateTable[spawnedCivilian->tileIndex06].ownerNationTag04;
    if (ownerTag < 0 || ownerTag >= kTerrainTypeDescriptorTableCount ||
        g_apTerrainTypeDescriptorTable[ownerTag] == 0) {
      FailScenario("\"recruited civilian tile has no terrain-owner descriptor\"");
      return;
    }

    if (spawnedCivilian->ownerNationSlot18 != nationSlot) {
      FailScenario("\"produced civilian is not owned by the active nation\"");
      return;
    }
    g_pGlobalMapState->DimByProspecting(spawnedCivilian);
    targetHillTile = FindProspectorTarget(kStrategicTerrainHills, true);
    targetSeaTile = FindProspectorTarget(kStrategicTerrainWater, false);
    if (targetHillTile == -1 || targetSeaTile == -1) {
      char failure[160];
      wsprintfA(failure, "\"prospector samples missing: eligible hill=%d prohibited sea=%d\"",
                targetHillTile, targetSeaTile);
      FailScenario(failure);
      return;
    }
    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(spawnedCivilian, 1);
    TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
    mapView->CenterOn(targetHillTile);
    EnterScenarioStep("ordering_recruited_civilian",
                      "selected_prospector_with_real_terrain_eligibility");
    VerifyProspectorOrdersAndCursors();
  }

  short FindProspectorTarget(StrategicTerrainKind terrainKind, bool mustBeEligible) {
    for (short tile = 0; tile < kGlobalMapTileCount; ++tile) {
      const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
      if (terrain.GetTerrainKind() != terrainKind || terrain.firstCivilianOrder20 != 0 ||
          tile == spawnedCivilian->tileIndex06 || tile % 0x6c == 0 || tile % 0x6c == 0x6b) {
        continue;
      }
      if ((terrain.recruitSearchVisited0e == 0) != mustBeEligible) {
        continue;
      }
      return tile;
    }
    return -1;
  }

  bool FindVisiblePointForTile(TMapDialog* mapDialog, short targetTile, CPoint* outPoint,
                               short* outBand) {
    for (int y = 1; y < mapDialog->frameHeight38; y += 2) {
      for (int x = 1; x < mapDialog->frameWidth34; x += 2) {
        short column;
        short row;
        short band;
        CPoint candidate(x, y);
        mapDialog->ConvertPoint(candidate, column, row, band);
        short tile = static_cast<short>(ComputeStridedRecordAddress6C(column, row));
        if (tile == targetTile) {
          *outPoint = candidate;
          *outBand = band;
          return true;
        }
      }
    }
    return false;
  }

  bool VerifyCursorForTile(TMapDialog* mapDialog, short targetTile, short expectedToken,
                           CPoint* outPoint) {
    TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
    mapView->CenterOn(targetTile);

    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);

    short band = 0;
    if (!FindVisiblePointForTile(mapDialog, targetTile, outPoint, &band)) {
      FailScenario("\"centered prospector target has no visible map hit point\"");
      return false;
    }

    unsigned short classifiedToken =
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(targetTile,
                                                                                       band);
    if (classifiedToken != expectedToken) {
      FailScenario("\"prospector cursor classifier disagrees with terrain eligibility\"");
      return false;
    }

    mapDialog->activeRegionBand72 = -1;
    mapDialog->cursorId4e = 0xffff;
    CPoint hostPoint(outPoint->x + mapDialog->absoluteX, outPoint->y + mapDialog->absoluteY);
    SendMessageA(mapDialog->nativeWindow50->m_hWnd, WM_MOUSEMOVE, 0,
                 MAKELPARAM(hostPoint.x, hostPoint.y));
    if (mapDialog->cursorId4e != expectedToken) {
      FailScenario("\"native prospector hover did not apply the classified cursor\"");
      return false;
    }

    HCURSOR expectedCursor =
        g_pUiRuntimeContext->turnEventCursors[expectedToken - TViewMgr::kCursorResourceIdBase];
    if (expectedCursor == 0 || GetCursor() != expectedCursor ||
        !CursorDrawsVisiblePixels(expectedCursor)) {
      FailScenario("\"classified prospector cursor is not visibly active\"");
      return false;
    }
    return true;
  }

  bool AnimationFrameBufferHasPixels(TAnimation* animation) {
    TQuickDrawSurfaceContext* surface = g_pUiAnimator->renderSurfaceContext;
    if (surface == 0 || surface->blitSurface.pixelBits == 0 ||
        surface->blitSurface.surfaceDib == 0 ||
        surface->blitSurface.surfaceDib->m_pInfoHeader == 0) {
      return false;
    }
    int height = surface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (height < 0) {
      height = -height;
    }
    int byteCount = surface->blitSurface.stride * height;
    memset(surface->blitSurface.pixelBits, 0, byteCount);
    animation->LoadFrameIntoBuffer();
    for (int index = 0; index < byteCount; ++index) {
      if (surface->blitSurface.pixelBits[index] != 0) {
        return true;
      }
    }
    return false;
  }

  bool HoverMovementRestoresPreviousTiles(TMapDialog* mapDialog) {
    HWND mapHost = mapDialog->nativeWindow50->m_hWnd;
    RedrawWindow(mapHost, 0, 0, RDW_INVALIDATE | RDW_UPDATENOW);

    DWORD* baseline = 0;
    int width = 0;
    int height = 0;
    if (!CaptureViewPixels(mapDialog, &baseline, &width, &height)) {
      return false;
    }

    CPoint firstPoint;
    CPoint secondPoint;
    short firstTile = -1;
    short secondTile = -1;
    for (int y = 32; y < mapDialog->frameHeight38 && secondTile == -1; y += 32) {
      for (int x = 32; x < mapDialog->frameWidth34; x += 32) {
        short column;
        short row;
        short band;
        CPoint point(x, y);
        mapDialog->ConvertPoint(point, column, row, band);
        short tile = static_cast<short>(ComputeStridedRecordAddress6C(column, row));
        if (tile == targetHillTile) {
          continue;
        }
        if (firstTile == -1) {
          firstPoint = point;
          firstTile = tile;
        } else if (tile != firstTile) {
          secondPoint = point;
          secondTile = tile;
          break;
        }
      }
    }
    if (secondTile == -1) {
      delete[] baseline;
      return false;
    }

    mapDialog->activeRegionBand72 = -1;
    CPoint firstHostPoint(firstPoint.x + mapDialog->absoluteX, firstPoint.y + mapDialog->absoluteY);
    CPoint secondHostPoint(secondPoint.x + mapDialog->absoluteX,
                           secondPoint.y + mapDialog->absoluteY);
    SendMessageA(mapHost, WM_MOUSEMOVE, 0, MAKELPARAM(firstHostPoint.x, firstHostPoint.y));
    SendMessageA(mapHost, WM_MOUSEMOVE, 0, MAKELPARAM(secondHostPoint.x, secondHostPoint.y));

    DWORD* afterMovement = 0;
    int afterWidth = 0;
    int afterHeight = 0;
    if (!CaptureViewPixels(mapDialog, &afterMovement, &afterWidth, &afterHeight) ||
        afterWidth != width || afterHeight != height) {
      delete[] afterMovement;
      delete[] baseline;
      return false;
    }

    short projectedY;
    short projectedX;
    ProjectTileIndexToWrappedScreenOffsetByScale(secondTile, &mapDialog->viewportOrigin60,
                                                 &projectedY, &projectedX, 1);
    CRect currentHoverRect(projectedX - 1, projectedY - 1, projectedX + 0x42, projectedY + 0x42);
    bool restored = true;
    for (int pixelY = 0; pixelY < height && restored; ++pixelY) {
      for (int pixelX = 0; pixelX < width; ++pixelX) {
        CPoint pixelPoint(pixelX, pixelY);
        if (!currentHoverRect.PtInRect(pixelPoint) &&
            baseline[pixelY * width + pixelX] != afterMovement[pixelY * width + pixelX]) {
          restored = false;
          break;
        }
      }
    }

    delete[] afterMovement;
    delete[] baseline;
    return restored;
  }

  TAnimation* RenderAndResolveOrderedProspectorAnimation(TMapUberPicture* mapView,
                                                         TMapDialog* mapDialog) {
    mapView->CenterOn(targetHillTile);
    TQuickDrawSurfaceContext* savedSurface;
    int savedSurfaceFlags;
    GetGWorld(&savedSurface, &savedSurfaceFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
    SetGWorld(savedSurface, savedSurfaceFlags);
    return g_pUiAnimator->FindRegisteredAnimationByTag(PointerAddressLong32(spawnedCivilian));
  }

  void VerifyProspectorOrdersAndCursors() {
    for (int index = 0; index < 0x36; ++index) {
      if (g_pUiRuntimeContext->turnEventCursors[index] == 0) {
        char failure[96];
        wsprintfA(failure, "\"turn-event cursor resource ~C%d did not load\"", index + 1000);
        FailScenario(failure);
        return;
      }
    }

    TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    if (mapDialog == 0) {
      FailScenario("\"strategic map has no map dialog for cursor verification\"");
      return;
    }

    TQuickDrawSurfaceContext* savedSurface;
    int savedSurfaceFlags;
    GetGWorld(&savedSurface, &savedSurfaceFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
    if (mapDialog->nativeWindow50 == 0 || mapDialog->nativeWindow50->m_hWnd == 0) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"strategic map has no native mouse-routing host\"");
      return;
    }

    CPoint hillPoint;
    CPoint seaPoint;
    if (spawnedCivilian->unitOrder != kUnitOrderIdle) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      WaitForScenarioTick(
          "\"new prospector did not settle into idle state before cursor verification\"");
      return;
    }
    if (!VerifyCursorForTile(mapDialog, targetSeaTile, 1008, &seaPoint)) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      return;
    }
    if (spawnedCivilian->unitOrder != kUnitOrderIdle) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"sea cursor verification changed the selected prospector order\"");
      return;
    }
    if (!VerifyCursorForTile(mapDialog, targetHillTile, 1001, &hillPoint)) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      return;
    }

    if (spawnedCivilian->unitOrder != kUnitOrderIdle ||
        spawnedCivilian->tileIndex06 == targetHillTile) {
      char failure[144];
      wsprintfA(failure, "\"prospector was not idle before click: order=%d tile=%d target=%d\"",
                spawnedCivilian->unitOrder, spawnedCivilian->tileIndex06, targetHillTile);
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario(failure);
      return;
    }
    if (!RuntimeUiDriver::ClickViewPointThroughNativeMessages(mapDialog, hillPoint.x,
                                                              hillPoint.y)) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"strategic map click could not be routed through its native host\"");
      return;
    }
    SetGWorld(savedSurface, savedSurfaceFlags);

    if (spawnedCivilian->unitOrder != kUnitOrderProspect ||
        spawnedCivilian->tileIndex06 != targetHillTile) {
      char failure[144];
      wsprintfA(failure, "\"prospector click mismatch: order=%d tile=%d target=%d\"",
                spawnedCivilian->unitOrder, spawnedCivilian->tileIndex06, targetHillTile);
      FailScenario(failure);
      return;
    }

    TCivUnit* tileCivilian =
        g_pGlobalMapState->GetTileUnitEntryByOwner(targetHillTile, g_pSimMgr->GetActiveNationId());
    TAnimation* animation = RenderAndResolveOrderedProspectorAnimation(mapView, mapDialog);
    int animationKind = animation != 0 ? animation->IsKindOf(RUNTIME_CLASS(TCivAnimation2)) : 0;
    int hasFramePixels = animation != 0 ? AnimationFrameBufferHasPixels(animation) : 0;
    if (tileCivilian != spawnedCivilian || animation == 0 || animationKind == 0 ||
        hasFramePixels == 0) {
      char failure[176];
      wsprintfA(failure, "\"prospector animation invalid: tile=%d animation=%d kind=%d pixels=%d\"",
                tileCivilian == spawnedCivilian, animation != 0, animationKind, hasFramePixels);
      FailScenario(failure);
      return;
    }

    initialAnimationFrame = animation->frameIndex;
    initialAnimationTick = animation->ticksSinceFrameChange;
    orderIssued = true;
    EnterScenarioStep("waiting_for_ordered_civilian_animation",
                      "verify_ordered_prospector_remains_visible_and_inspectable");
    RequestScenarioTick();
  }

  void VerifyOrderedProspectorRemainsVisibleAndInspectable() {
    TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    if (mapDialog == 0) {
      FailScenario("\"strategic map disappeared while the prospector order was active\"");
      return;
    }

    TAnimation* animation = RenderAndResolveOrderedProspectorAnimation(mapView, mapDialog);
    TCivUnit* tileCivilian =
        g_pGlobalMapState->GetTileUnitEntryByOwner(targetHillTile, g_pSimMgr->GetActiveNationId());
    unsigned short reportCursor =
        g_pSelectedCivilianOrderState->ResolveCivilianTileSelectionOrReportActionCode(
            targetHillTile, 0);
    int animationAdvanced =
        animation != 0 && (animation->frameIndex != initialAnimationFrame ||
                           animation->ticksSinceFrameChange != initialAnimationTick);
    int hasFramePixels = animation != 0 ? AnimationFrameBufferHasPixels(animation) : 0;
    if (tileCivilian != spawnedCivilian || animation == 0 || animationAdvanced == 0 ||
        reportCursor != 0x3f3 || hasFramePixels == 0) {
      char failure[240];
      wsprintfA(failure,
                "\"ordered prospector validation failed: tile=%d animation=%d advanced=%d "
                "frame=%d/%d tick=%d/%d cursor=%d pixels=%d\"",
                tileCivilian == spawnedCivilian, animation != 0, animationAdvanced,
                animation == 0 ? -1 : animation->frameIndex, initialAnimationFrame,
                animation == 0 ? -1 : animation->ticksSinceFrameChange, initialAnimationTick,
                reportCursor, hasFramePixels);
      FailScenario(failure);
      return;
    }
    if (!HoverMovementRestoresPreviousTiles(mapDialog)) {
      FailScenario("\"ordered prospector hover left stale map pixels outside the current tile\"");
      return;
    }
    Pass();
  }

  TCivUnit* spawnedCivilian;
  short targetHillTile;
  short targetSeaTile;
  bool orderIssued;
  short initialAnimationFrame;
  int initialAnimationTick;
};

CivilianRecruitmentTestCase g_test;

} // namespace

RuntimeTestCase* CivilianRecruitmentTest() {
  return &g_test;
}
