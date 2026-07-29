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
#include "game/city_ui/TEngineerDialog.h"
#include "game/city_ui/TLongintList.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/globals/view_registries.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/pointer_representation.h"
#include "game/strategic_terrain.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_widgets/TCivDescription.h"
#include "game/ui_widgets/TCivToolbar.h"
#include "game/ui_widgets/TDeluxeText.h"

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

bool CompletedFarmerImprovementChangesTilePixels(TMapDialog* mapDialog, short tileIndex,
                                                 unsigned char initialClass,
                                                 unsigned char completedClass) {
  TBitmapSurfaceNode** surfaceHandle = GetGWorldPixMap(mapDialog->quickDrawSurface350);
  if (surfaceHandle == 0 || *surfaceHandle == 0 || !LockPixels(surfaceHandle)) {
    return false;
  }

  TBitmapSurfaceNode* surface = *surfaceHandle;
  int stride = surface->stride & 0x3fff;
  unsigned char before[0x1000];
  unsigned char after[0x1000];
  TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tileIndex];
  unsigned char savedDevelopmentClasses = terrain.developmentClassNibbles0c;
  TQuickDrawSurfaceContext* savedSurface;
  int savedSurfaceFlags;
  GetGWorld(&savedSurface, &savedSurfaceFlags);
  SetGWorld(mapDialog->quickDrawSurface350, savedSurfaceFlags);

  terrain.developmentClassNibbles0c =
      static_cast<unsigned char>((savedDevelopmentClasses & 0xf0) | initialClass);
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  for (int row = 0; row < 0x40; ++row) {
    memcpy(before + row * 0x40, surface->pixelBits + row * stride, 0x40);
  }

  terrain.developmentClassNibbles0c =
      static_cast<unsigned char>((savedDevelopmentClasses & 0xf0) | completedClass);
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  for (int afterRow = 0; afterRow < 0x40; ++afterRow) {
    memcpy(after + afterRow * 0x40, surface->pixelBits + afterRow * stride, 0x40);
  }

  terrain.developmentClassNibbles0c = savedDevelopmentClasses;
  mapDialog->DrawOneTile(tileIndex, 0, 0);
  SetGWorld(savedSurface, savedSurfaceFlags);
  UnlockPixels(surfaceHandle);
  return memcmp(before, after, sizeof(before)) != 0;
}

class CivilianRecruitmentTestCase : public RandomGameScenario {
public:
  CivilianRecruitmentTestCase()
      : spawnedCivilian(0), targetHillTile(-1), targetSeaTile(-1), targetSurveyMissTile(-1),
        farmer(0), targetFarmerTile(-1), initialFarmerImprovementClass(0), orderIssued(false),
        completionIssued(false), completionVerified(false), surveyMissActionInProgress(false),
        surveyMissOrderIssued(false), surveyMissCompletionIssued(false),
        surveyMissCompletionVerified(false), farmerActionInProgress(false),
        farmerOrderIssued(false), farmerCompletionIssued(false), farmerCompletionVerified(false),
        engineerActionIssued(false), engineerDialogObserved(false), initialAnimationFrame(0),
        initialAnimationTick(0) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    spawnedCivilian = 0;
    orderIssued = false;
    EnterScenarioStep("recruiting_civilian", "produce_and_select_recruited_civilian");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (surveyMissActionInProgress || farmerActionInProgress) {
      return;
    }
    if (engineerActionIssued) {
      VerifyEngineerDialogAndCancel();
      return;
    }
    if (spawnedCivilian == 0) {
      RecruitCivilian();
      return;
    }

    if (!orderIssued) {
      VerifyProspectorOrdersAndCursors();
      return;
    }

    if (completionIssued) {
      if (!completionVerified) {
        VerifyCompletedProspectorSurveyMark();
      } else if (!surveyMissOrderIssued) {
        IssueUnsuccessfulProspectorSurvey();
      } else if (!surveyMissCompletionIssued) {
        CompleteUnsuccessfulProspectorSurvey();
      } else if (!surveyMissCompletionVerified) {
        VerifyUnsuccessfulProspectorSurveyMark();
      } else if (!farmerOrderIssued) {
        VerifyFarmerWorkableTileSelection();
      } else if (!farmerCompletionIssued) {
        CompleteFarmerImprovement();
      } else if (!farmerCompletionVerified) {
        VerifyFarmerImprovementVisual();
      } else {
        OpenEngineerConstructionDialogThroughMap();
      }
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
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
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
    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(spawnedCivilian, 1);
    targetHillTile = FindProspectorTarget(kStrategicTerrainHills, true);
    targetSeaTile = FindProspectorTarget(kStrategicTerrainWater, false);
    if (targetHillTile == -1 || targetSeaTile == -1) {
      char failure[160];
      wsprintfA(failure, "\"prospector samples missing: eligible hill=%d prohibited sea=%d\"",
                targetHillTile, targetSeaTile);
      FailScenario(failure);
      return;
    }
    TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
    mapView->CenterOn(targetHillTile);
    EnterScenarioStep("ordering_recruited_civilian",
                      "selected_prospector_with_real_terrain_eligibility");
    VerifyProspectorOrdersAndCursors();
  }

  short FindProspectorTarget(StrategicTerrainKind terrainKind, bool mustBeEligible) {
    for (short tile = 0; tile < kGlobalMapTileCount; ++tile) {
      const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tile];
      if (terrain.GetTerrainKind() != terrainKind || terrain.firstCivilianOrder20 != 0 ||
          tile == spawnedCivilian->tileIndex06 || tile % 0x6c == 0 || tile % 0x6c == 0x6b) {
        continue;
      }
      if ((terrain.recruitSearchVisited0e == 0) != mustBeEligible) {
        continue;
      }
      if (mustBeEligible && g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(tile) == 0) {
        continue;
      }
      if (mustBeEligible) {
        bool hasUndevelopedResource = false;
        for (int edge = 0; edge < 2; ++edge) {
          if (terrain.resourceTypeByEdge[edge] >= 0 &&
              g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(tile, edge == 0) == 0) {
            hasUndevelopedResource = true;
          }
        }
        if (!hasUndevelopedResource) {
          continue;
        }
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
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
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

    mapDialog->activeRegionBand = -1;
    mapDialog->cursorId4e = 0xffff;
    CPoint hostPoint(outPoint->x + mapDialog->absoluteX, outPoint->y + mapDialog->absoluteY);
    SendMessageA(mapDialog->nativeWindow50->m_hWnd, WM_MOUSEMOVE, 0,
                 MAKELPARAM(hostPoint.x, hostPoint.y));
    if (mapDialog->cursorId4e != expectedToken) {
      FailScenario("\"native prospector hover did not apply the classified cursor\"");
      return false;
    }

    HCURSOR expectedCursor =
        g_pViewMgr->turnEventCursors[expectedToken - TViewMgr::kCursorResourceIdBase];
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

    mapDialog->activeRegionBand = -1;
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
    ProjectTileIndexToWrappedScreenOffsetByScale(secondTile, &mapDialog->viewportOrigin,
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

  int CollectProspectorLegendTargets(short ownerNation, short profile, short* targetTiles) {
    TLongintList* provinces = g_apTerrainTypeDescriptorTable[ownerNation]->ownedRegionList;
    int candidateCount = 0;
    for (int provinceOrdinal = 1; provinceOrdinal <= provinces->GetSize(); ++provinceOrdinal) {
      Province* province = &g_pGlobalMapState->cityScoreTable[provinces->At(provinceOrdinal)];
      for (int tileOrdinal = 0; tileOrdinal < province->linkedRegionCount; ++tileOrdinal) {
        short tileIndex = province->linkedTileIndices42[tileOrdinal];
        TTerrainStateRecord* terrain = &g_pGlobalMapState->terrainStateTable[tileIndex];
        if (terrain->recruitSearchVisited0e != 0 ||
            static_cast<unsigned char>(terrain->gateFlag) != profile) {
          continue;
        }
        if (targetTiles != 0) {
          targetTiles[candidateCount] = tileIndex;
        }
        ++candidateCount;
      }
    }
    return candidateCount;
  }

  bool SameMapOrigin(const CPoint& left, const CPoint& right) {
    return left.x == right.x && left.y == right.y;
  }

  bool VerifyProspectorLegendCameraCycling(TMapUberPicture* mapView, TMapDialog* mapDialog) {
    TCivToolbar* toolbar = static_cast<TCivToolbar*>(mapView->categoryPages[0]);
    TCivDescription* description =
        toolbar != 0 ? static_cast<TCivDescription*>(toolbar->ResolveControlByTag(kControlTagBack))
                     : 0;
    if (description == 0 ||
        description->selectedCivilianClass != EncodeCivilianUnitKind(kCivilianUnitProspector)) {
      FailScenario("\"selected prospector has no civilian legend control\"");
      return false;
    }

    CRect descriptionBounds(0, 0, description->frameWidth34, description->frameHeight38);
    description->Draw(&descriptionBounds);

    int selectedColumn = -1;
    short selectedProfile = -1;
    int candidateCount = 0;
    int visibleColumnCount =
        g_pTechMgr->orderCapRows277[g_pSimMgr->GetActiveNationId()].techStatusByTechId[4] == 2 ? 5
                                                                                               : 2;
    for (int column = 0; column < visibleColumnCount; ++column) {
      short profile = g_anTargetTileProfileByCivilianClassAndSlot[5 + column];
      RECT* legendRect = &description->legendRects[profile];
      if (legendRect->right <= legendRect->left || legendRect->bottom <= legendRect->top) {
        continue;
      }
      int count = CollectProspectorLegendTargets(description->ownerNationId, profile, 0);
      if (count >= 2 && (selectedColumn == -1 || count < candidateCount)) {
        selectedColumn = column;
        selectedProfile = profile;
        candidateCount = count;
      }
    }
    if (selectedColumn == -1 ||
        description->targetTileCountsBySlot[selectedColumn] != candidateCount) {
      char failure[192];
      wsprintfA(failure,
                "\"prospector legend target mismatch: column=%d profile=%d candidates=%d "
                "shown=%d counter=%d owner=%d\"",
                selectedColumn, selectedProfile, candidateCount,
                selectedColumn < 0 ? -1 : description->targetTileCountsBySlot[selectedColumn],
                selectedProfile < 0 ? -1 : g_awCivilianLegendSelectionCountsBySlot[selectedProfile],
                description->ownerNationId);
      FailScenario(failure);
      return false;
    }

    short targetTiles[kGlobalMapTileCount];
    CPoint targetOrigins[kGlobalMapTileCount];
    CollectProspectorLegendTargets(description->ownerNationId, selectedProfile, targetTiles);
    for (int candidateOrdinal = 0; candidateOrdinal < candidateCount; ++candidateOrdinal) {
      mapDialog->CenterOn(targetTiles[candidateOrdinal]);
      targetOrigins[candidateOrdinal] = mapDialog->viewportOrigin;
    }
    mapDialog->CenterOn(targetSeaTile);

    RECT* legendRect = &description->legendRects[selectedProfile];
    int clickX = (legendRect->left + legendRect->right) / 2;
    int clickY = (legendRect->top + legendRect->bottom) / 2;
    int centeredClickCount = 0;
    bool observedCounterWrap = false;
    int clickLimit = candidateCount + 3;
    for (int clickOrdinal = 0; clickOrdinal < clickLimit && centeredClickCount < candidateCount + 1;
         ++clickOrdinal) {
      unsigned short counterBefore = g_awCivilianLegendSelectionCountsBySlot[selectedProfile];
      CPoint originBefore = mapDialog->viewportOrigin;
      if (!RuntimeUiDriver::ClickViewPointThroughNativeMessages(description, clickX, clickY)) {
        FailScenario("\"prospector legend target traversal lost its native click path\"");
        return false;
      }
      unsigned short counterAfter = g_awCivilianLegendSelectionCountsBySlot[selectedProfile];
      if (counterBefore < candidateCount) {
        if (counterAfter != counterBefore + 1 ||
            !SameMapOrigin(mapDialog->viewportOrigin, targetOrigins[counterBefore])) {
          FailScenario("\"prospector legend click did not center its indexed retail target\"");
          return false;
        }
        ++centeredClickCount;
      } else {
        if (counterAfter != counterBefore % candidateCount ||
            !SameMapOrigin(mapDialog->viewportOrigin, originBefore)) {
          FailScenario("\"prospector legend exhaustion did not apply the retail counter reset\"");
          return false;
        }
        observedCounterWrap = true;
      }
    }
    if (!observedCounterWrap || centeredClickCount != candidateCount + 1) {
      FailScenario("\"prospector legend selection did not cycle through the first tile again\"");
      return false;
    }
    return true;
  }

  void VerifyProspectorOrdersAndCursors() {
    for (int index = 0; index < 0x36; ++index) {
      if (g_pViewMgr->turnEventCursors[index] == 0) {
        char failure[96];
        wsprintfA(failure, "\"turn-event cursor resource ~C%d did not load\"", index + 1000);
        FailScenario(failure);
        return;
      }
    }

    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
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
    if (!VerifyProspectorLegendCameraCycling(mapView, mapDialog)) {
      SetGWorld(savedSurface, savedSurfaceFlags);
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
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
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
    spawnedCivilian->TickCivWorkOrderCountdownAndComplete();
    completionIssued = true;
    EnterScenarioStep("completing_prospector_order",
                      "verify_survey_mark_through_strategic_map_renderer");
    RequestScenarioTick();
  }

  void VerifyCompletedProspectorSurveyMark() {
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    if (mapDialog == 0) {
      FailScenario("\"strategic map disappeared before prospector completion was rendered\"");
      return;
    }

    const int activeNation = g_pSimMgr->GetActiveNationId();
    const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[targetHillTile];
    if (spawnedCivilian->unitOrder != kUnitOrderIdle || spawnedCivilian->remainingTurns24 > 0 ||
        (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) == 0 ||
        spawnedCivilian->completionMarker26 != 0x232f ||
        g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(targetHillTile) == 0) {
      char failure[240];
      wsprintfA(failure,
                "\"prospector completion mismatch: order=%d remaining=%d survey=%d marker=%d "
                "candidate=%d\"",
                spawnedCivilian->unitOrder, spawnedCivilian->remainingTurns24,
                (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) != 0,
                spawnedCivilian->completionMarker26,
                g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(targetHillTile));
      FailScenario(failure);
      return;
    }

    bool observableResource = false;
    bool resourceIconRendered = false;
    for (int edge = 0; edge < 2; ++edge) {
      const short resourceType = terrain.resourceTypeByEdge[edge];
      const int improvementClass =
          g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(targetHillTile, edge == 0);
      if (resourceType < 0 || improvementClass != 0) {
        continue;
      }
      observableResource = true;
      ObserveStrategicMapResourceTileForRuntimeTest(targetHillTile, resourceType);
      mapView->CenterOn(targetHillTile);
      mapView->RedrawTile(targetHillTile);
      TQuickDrawSurfaceContext* savedSurface;
      int savedSurfaceFlags;
      GetGWorld(&savedSurface, &savedSurfaceFlags);
      SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
      CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
      mapDialog->Draw(&mapBounds);
      SetGWorld(savedSurface, savedSurfaceFlags);
      if (WasStrategicMapResourceTileObservedForRuntimeTest()) {
        resourceIconRendered = true;
        break;
      }
    }
    if (!observableResource || !resourceIconRendered) {
      FailScenario("\"completed prospector survey did not reach the strategic resource renderer\"");
      return;
    }

    completionVerified = true;
    EnterScenarioStep("selecting_farmer_for_workable_tile_verification",
                      "resume_through_normal_map_event_tick");
    RequestScenarioTick();
  }

  bool IsProspectableResource(signed char resourceType) {
    return resourceType == kResourceCoal || resourceType == kResourceIron ||
           resourceType == kResourceOil || resourceType == kResourceGems ||
           resourceType == kResourceGold;
  }

  void IssueUnsuccessfulProspectorSurvey() {
    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(spawnedCivilian, 1);
    const int activeNation = g_pSimMgr->GetActiveNationId();
    int eligibleCount = 0;
    int nonMineralCount = 0;
    int undiscoveredCount = 0;
    int orderableCount = 0;
    for (short tile = 0; tile < kGlobalMapTileCount; ++tile) {
      const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tile];
      if (tile == spawnedCivilian->tileIndex06 || tile % 0x6c == 0 || tile % 0x6c == 0x6b ||
          terrain.firstCivilianOrder20 != 0 || terrain.recruitSearchVisited0e != 0 ||
          (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) != 0) {
        continue;
      }
      ++eligibleCount;
      if (IsProspectableResource(terrain.resourceTypeByEdge[0])) {
        continue;
      }
      ++nonMineralCount;
      if (g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(tile) != 0) {
        continue;
      }
      ++undiscoveredCount;
      if (g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(tile, 0) != 8) {
        continue;
      }
      ++orderableCount;
      targetSurveyMissTile = tile;
      break;
    }
    if (targetSurveyMissTile == -1) {
      char failure[192];
      wsprintfA(failure,
                "\"no unsuccessful prospecting tile: eligible=%d nonmineral=%d undiscovered=%d "
                "orderable=%d\"",
                eligibleCount, nonMineralCount, undiscoveredCount, orderableCount);
      FailScenario(failure);
      return;
    }

    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    CPoint targetPoint;
    if (mapDialog == 0) {
      FailScenario("\"strategic map disappeared before unsuccessful prospecting\"");
      return;
    }
    TQuickDrawSurfaceContext* savedSurface;
    int savedSurfaceFlags;
    GetGWorld(&savedSurface, &savedSurfaceFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
    mapView->CenterOn(targetSurveyMissTile);
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
    short targetBand;
    if (!FindVisiblePointForTile(mapDialog, targetSurveyMissTile, &targetPoint, &targetBand) ||
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(
            targetSurveyMissTile, targetBand) != 1001) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"unsuccessful prospecting tile lost its retail cursor route\"");
      return;
    }
    surveyMissActionInProgress = true;
    const bool clickHandled = RuntimeUiDriver::ClickViewPointThroughNativeMessages(
        mapDialog, targetPoint.x, targetPoint.y);
    surveyMissActionInProgress = false;
    if (!clickHandled) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"unsuccessful prospecting click did not reach the strategic map\"");
      return;
    }
    SetGWorld(savedSurface, savedSurfaceFlags);
    if (spawnedCivilian->unitOrder != kUnitOrderProspect ||
        spawnedCivilian->tileIndex06 != targetSurveyMissTile) {
      FailScenario("\"non-mineral tile did not receive the retail prospecting order\"");
      return;
    }

    surveyMissOrderIssued = true;
    EnterScenarioStep("completing_unsuccessful_prospector_order",
                      "real_non_mineral_tile_order_reaches_completion");
    RequestScenarioTick();
  }

  void CompleteUnsuccessfulProspectorSurvey() {
    g_pUiAnimator->DoIdle(1);
    spawnedCivilian->TickCivWorkOrderCountdownAndComplete();
    surveyMissCompletionIssued = true;
    RequestScenarioTick();
  }

  void VerifyUnsuccessfulProspectorSurveyMark() {
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    const int activeNation = g_pSimMgr->GetActiveNationId();
    const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[targetSurveyMissTile];
    if (mapDialog == 0 || spawnedCivilian->unitOrder != kUnitOrderIdle ||
        spawnedCivilian->remainingTurns24 > 0 ||
        (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) == 0 ||
        IsProspectableResource(terrain.resourceTypeByEdge[0]) ||
        g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(targetSurveyMissTile) != 0) {
      FailScenario("\"unsuccessful prospecting did not produce the retail surveyed state\"");
      return;
    }

    ObserveStrategicMapSurveyMissTileForRuntimeTest(targetSurveyMissTile);
    mapView->CenterOn(targetSurveyMissTile);
    mapView->RedrawTile(targetSurveyMissTile);
    TQuickDrawSurfaceContext* savedSurface;
    int savedSurfaceFlags;
    GetGWorld(&savedSurface, &savedSurfaceFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
    SetGWorld(savedSurface, savedSurfaceFlags);
    if (!WasStrategicMapSurveyMissTileObservedForRuntimeTest()) {
      FailScenario("\"surveyed non-mineral tile did not reach the retail miss-mark blit\"");
      return;
    }

    surveyMissCompletionVerified = true;
    EnterScenarioStep("selecting_farmer_for_workable_tile_verification",
                      "resume_through_normal_map_event_tick");
    RequestScenarioTick();
  }

  bool IsRetailFarmerWorkableTile(const TTerrainStateRecord& terrain, short nationSlot,
                                  short orderType) {
    if (terrain.ownerNationTag04 != nationSlot && terrain.secondaryOwnerNationTag18 != nationSlot) {
      return false;
    }
    if (g_abGateFlagQualifies[terrain.gateFlag] == 0) {
      return false;
    }

    short maximumDevelopmentClass = 0;
    for (int edge = 0; edge < 2; ++edge) {
      const signed char resourceType = terrain.resourceTypeByEdge[edge];
      if (resourceType == -1 || g_anResourceTypeRequiredOrderType[resourceType] != orderType ||
          (g_abResourceTypeAlwaysQualifies[resourceType] == 0 &&
           terrain.ownerNationTag04 != nationSlot)) {
        continue;
      }
      const short capability =
          g_pTechMgr->capabilityValueByNationAndResource[nationSlot][resourceType];
      if (capability > maximumDevelopmentClass) {
        maximumDevelopmentClass = capability;
      }
    }
    return static_cast<signed char>(terrain.developmentClassNibbles0c & 0xf) <
           maximumDevelopmentClass;
  }

  void VerifyFarmerWorkableTileSelection() {
    EnterScenarioStep("recruiting_farmer_for_selection_test", "produce_farmer_through_city_order");
    TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    const int oldPersistentUnitId = g_pSimMgr->field_64;
    TUnitOrder recruitOrder;
    recruitOrder.IUnitOrder(nation->city, EncodeCivilianUnitKind(kCivilianUnitFarmer), 0, 0, -1, 0,
                            0, kLowSkillWorkforceMode, 0);
    recruitOrder.quantity = 1;
    recruitOrder.Produce();

    farmer = 0;
    for (int ordinal = 1; ordinal <= nation->trackedObjectList->GetCount(); ++ordinal) {
      CObject* entry = static_cast<CObject*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      if (entry != 0 && entry->IsKindOf(RUNTIME_CLASS(TCivUnit)) != 0) {
        TCivUnit* civilian = static_cast<TCivUnit*>(entry);
        if (civilian->persistentUnitId20 == oldPersistentUnitId + 1) {
          farmer = civilian;
          break;
        }
      }
    }
    if (farmer == 0 || farmer->GetCivilianUnitKind() != kCivilianUnitFarmer ||
        farmer->unitOrder != kUnitOrderIdle) {
      FailScenario("\"farmer production did not yield an idle farmer\"");
      return;
    }

    EnterScenarioStep("selecting_farmer_through_civilian_manager",
                      "dispatch_retail_farmer_workable_predicate");
    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(farmer, 0);
    const short nationSlot = farmer->ownerNationSlot18;
    short workableTile = -1;
    short moveTile = -1;
    short prohibitedTile = -1;
    int predicateMismatches = 0;
    for (short tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
      const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tileIndex];
      const bool expectedWorkable =
          IsRetailFarmerWorkableTile(terrain, nationSlot, farmer->orderType);
      if ((terrain.recruitSearchVisited0e == 0) != expectedWorkable) {
        ++predicateMismatches;
      }

      const int action =
          g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(tileIndex, 0);
      TCivUnit* clickedUnit = g_pGlobalMapState->GetTileUnitEntryByOwner(tileIndex, nationSlot);
      const signed char firstResourceType = terrain.resourceTypeByEdge[0];
      const bool firstResourceCanBeImproved =
          firstResourceType >= 0 &&
          g_anResourceTypeRequiredOrderType[firstResourceType] == farmer->orderType &&
          (g_abResourceTypeAlwaysQualifies[firstResourceType] != 0 ||
           terrain.ownerNationTag04 == nationSlot) &&
          static_cast<signed char>(terrain.developmentClassNibbles0c & 0xf) <
              g_pTechMgr->capabilityValueByNationAndResource[nationSlot][firstResourceType];
      if (expectedWorkable && firstResourceCanBeImproved && clickedUnit == 0 && action == 9 &&
          workableTile == -1) {
        workableTile = tileIndex;
      } else if (!expectedWorkable && clickedUnit == 0 && action == 3 && moveTile == -1) {
        moveTile = tileIndex;
      } else if (!expectedWorkable && clickedUnit == 0 && action == 1 && prohibitedTile == -1) {
        prohibitedTile = tileIndex;
      }
    }

    const int occupiedAction = g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(
        spawnedCivilian->tileIndex06, 0);
    EnterScenarioStep("checking_farmer_tile_actions", "verify_reach_occupancy_and_cursor_routes");
    if (predicateMismatches != 0 || workableTile == -1 || moveTile == -1 || prohibitedTile == -1 ||
        occupiedAction != 2) {
      char failure[240];
      wsprintfA(failure,
                "\"farmer selection mismatch: predicates=%d workable=%d move=%d prohibited=%d "
                "occupied=%d\"",
                predicateMismatches, workableTile, moveTile, prohibitedTile, occupiedAction);
      FailScenario(failure);
      return;
    }

    if (g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(workableTile, 0) != 9 ||
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(
            workableTile, 0) != g_civilianTileOrderCursorTokenTable[9]) {
      FailScenario("\"farmer workable tile did not retain the retail action and cursor route\"");
      return;
    }

    EnterScenarioStep("verifying_farmer_workable_tiles",
                      "retail_predicate_reach_and_occupancy_match_real_selection");
    targetFarmerTile = workableTile;
    initialFarmerImprovementClass = static_cast<short>(
        g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(targetFarmerTile, 0));

    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    CPoint targetPoint;
    short targetBand;
    if (mapDialog == 0) {
      FailScenario("\"strategic map disappeared before farmer improvement order\"");
      return;
    }
    TQuickDrawSurfaceContext* savedSurface;
    int savedSurfaceFlags;
    GetGWorld(&savedSurface, &savedSurfaceFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
    mapView->CenterOn(targetFarmerTile);
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
    if (!FindVisiblePointForTile(mapDialog, targetFarmerTile, &targetPoint, &targetBand) ||
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(
            targetFarmerTile, targetBand) != g_civilianTileOrderCursorTokenTable[9]) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"farmer improvement tile lost its retail cursor route\"");
      return;
    }

    farmerActionInProgress = true;
    const bool clickHandled = RuntimeUiDriver::ClickViewPointThroughNativeMessages(
        mapDialog, targetPoint.x, targetPoint.y);
    farmerActionInProgress = false;
    SetGWorld(savedSurface, savedSurfaceFlags);
    if (!clickHandled || farmer->unitOrder != kUnitOrderDevelopResource ||
        farmer->tileIndex06 != targetFarmerTile) {
      FailScenario("\"farmer click did not queue the retail resource improvement order\"");
      return;
    }

    farmerOrderIssued = true;
    EnterScenarioStep("completing_farmer_improvement",
                      "real_farmer_order_reaches_map_state_completion");
    RequestScenarioTick();
  }

  void CompleteFarmerImprovement() {
    g_pUiAnimator->DoIdle(1);
    farmer->TickCivWorkOrderCountdownAndComplete();
    farmerCompletionIssued = farmer->unitOrder == kUnitOrderIdle;
    RequestScenarioTick();
  }

  void VerifyFarmerImprovementVisual() {
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[targetFarmerTile];
    const short improvementClass = static_cast<short>(
        g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(targetFarmerTile, 0));
    const short resourceType = terrain.resourceTypeByEdge[0];
    if (mapDialog == 0 || farmer->unitOrder != kUnitOrderIdle || farmer->remainingTurns24 > 0 ||
        improvementClass != initialFarmerImprovementClass + 1 || resourceType < 0 ||
        g_anResourceTypeRequiredOrderType[resourceType] != farmer->orderType) {
      FailScenario("\"farmer completion did not advance the retail improvement state\"");
      return;
    }

    ObserveStrategicMapImprovementTileForRuntimeTest(targetFarmerTile, resourceType,
                                                     improvementClass);
    mapView->CenterOn(targetFarmerTile);
    mapView->RedrawTile(targetFarmerTile);
    TQuickDrawSurfaceContext* savedSurface;
    int savedSurfaceFlags;
    GetGWorld(&savedSurface, &savedSurfaceFlags);
    SetGWorld(g_pPrimaryRenderSurfaceContext, savedSurfaceFlags);
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
    SetGWorld(savedSurface, savedSurfaceFlags);
    if (!WasStrategicMapImprovementTileObservedForRuntimeTest() ||
        !CompletedFarmerImprovementChangesTilePixels(
            mapDialog, targetFarmerTile, static_cast<unsigned char>(initialFarmerImprovementClass),
            static_cast<unsigned char>(improvementClass))) {
      FailScenario("\"completed farmer improvement did not change the rendered tile pixels\"");
      return;
    }

    farmerCompletionVerified = true;
    EnterScenarioStep("verifying_farmer_improvement_visual",
                      "completed_low_nibble_improvement_reaches_production_renderer");
    RequestScenarioTick();
  }

  void OpenEngineerConstructionDialogThroughMap() {
    TGreatPower* nation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    int oldPersistentUnitId = g_pSimMgr->field_64;
    TUnitOrder recruitOrder;
    recruitOrder.IUnitOrder(nation->city, EncodeCivilianUnitKind(kCivilianUnitEngineer), 0, 0, -1,
                            0, 0, kLowSkillWorkforceMode, 0);
    recruitOrder.quantity = 1;
    recruitOrder.Produce();

    TCivUnit* engineer = 0;
    for (int ordinal = 1; ordinal <= nation->trackedObjectList->GetCount(); ++ordinal) {
      CObject* entry = static_cast<CObject*>(nation->trackedObjectList->GetEntryByOrdinal(ordinal));
      if (entry != 0 && entry->IsKindOf(RUNTIME_CLASS(TCivUnit)) != 0) {
        TCivUnit* civilian = static_cast<TCivUnit*>(entry);
        if (civilian->persistentUnitId20 == oldPersistentUnitId + 1) {
          engineer = civilian;
          break;
        }
      }
    }
    if (engineer == 0 || engineer->GetCivilianUnitKind() != kCivilianUnitEngineer ||
        engineer->unitOrder != kUnitOrderIdle) {
      FailScenario("\"engineer production did not yield an idle engineer\"");
      return;
    }

    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(engineer, 1);
    short engineerTile = engineer->tileIndex06;
    int engineerAction =
        g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(engineerTile, 0);
    if (engineerAction != 4) {
      for (short tile = 0; tile < kGlobalMapTileCount; ++tile) {
        const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tile];
        if (terrain.ownerNationTag04 == engineer->ownerNationSlot18 &&
            terrain.firstCivilianOrder20 == 0) {
          engineer->MoveTo(tile);
          g_pSelectedCivilianOrderState->SetActiveCivilianSelection(engineer, 1);
          engineerTile = tile;
          engineerAction =
              g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(engineerTile, 0);
          if (engineerAction == 4) {
            break;
          }
        }
      }
    }
    if (engineerAction != 4) {
      FailScenario("\"selected engineer's occupied tile did not resolve to the build action\"");
      return;
    }

    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    TMapDialog* mapDialog = mapView != 0 ? mapView->subview2A8 : 0;
    CPoint engineerPoint;
    short band;
    if (mapDialog == 0) {
      FailScenario("\"strategic map disappeared before the engineer build action\"");
      return;
    }
    mapView->CenterOn(engineerTile);
    if (!FindVisiblePointForTile(mapDialog, engineerTile, &engineerPoint, &band)) {
      FailScenario("\"selected engineer tile has no visible map hit point\"");
      return;
    }

    engineerActionIssued = true;
    EnterScenarioStep("opening_engineer_construction_dialog",
                      "native_click_on_selected_engineer_tile");
    if (!RuntimeUiDriver::ClickViewPointThroughNativeMessages(mapDialog, engineerPoint.x,
                                                              engineerPoint.y)) {
      FailScenario("\"engineer build click could not be routed through the map host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyEngineerDialogAndCancel() {
    if (g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"engineer construction dialog did not open\"");
      return;
    }
    TWindow* modal = g_ModalViewStack.GetHead();
    TView* dialog = modal->ResolveControlByTag(kControlTagDialog);
    TStaticText* title =
        dialog != 0 ? static_cast<TStaticText*>(dialog->ResolveControlByTag(kControlTagTitl)) : 0;
    TView* cancel = modal->ResolveControlByTag(kControlTagCncl);
    if (dialog == 0 || dialog->IsKindOf(RUNTIME_CLASS(TEngineerDialog)) == 0 || title == 0 ||
        cancel == 0) {
      RecordUnexpectedModalView(modal);
      FailScenario("\"engineer construction dialog does not match the retail resource tree\"");
      return;
    }

    CString titleText;
    title->CopyTextTo(&titleText);
    int optionButtonCount = 0;
    int optionLabelCount = 0;
    int nonemptyOptionLabelCount = 0;
    POSITION childPosition = dialog->childList44->GetHeadPosition();
    while (childPosition != 0) {
      TView* child = dialog->childList44->GetNext(childPosition);
      if (child->controlTag == kControlTagFort || child->controlTag == kSummaryTagRail ||
          child->controlTag == kControlTagPort) {
        ++optionButtonCount;
        if (child->frameWidth34 != 0x26 || child->frameHeight38 != 0x20) {
          FailScenario("\"engineer option button does not use the retail 38x32 frame\"");
          return;
        }
      }
      if (child->IsKindOf(RUNTIME_CLASS(TDeluxeText)) != 0) {
        TDeluxeText* label = static_cast<TDeluxeText*>(child);
        ++optionLabelCount;
        if (label->frameWidth34 != 0xec || label->frameHeight38 != 0x26) {
          FailScenario("\"engineer option label does not match the retail resource layout\"");
          return;
        }
        CString labelText;
        label->CopyTextTo(&labelText);
        if (!labelText.IsEmpty()) {
          ++nonemptyOptionLabelCount;
        }
      }
    }

    if (titleText.IsEmpty() || optionButtonCount == 0 || optionLabelCount != optionButtonCount ||
        nonemptyOptionLabelCount != optionLabelCount || dialog->frameHeight38 <= 0x46 ||
        modal->frameHeight38 != dialog->frameHeight38 || cancel->ownerLocalX != 0x11 ||
        cancel->ownerLocalY != dialog->frameHeight38 - 0x20 || cancel->frameWidth34 != 0x3d ||
        cancel->frameHeight38 != 0x18 ||
        modal->GetDialogBehavior()->defaultCommandCode != kControlTagCncl) {
      FailScenario("\"engineer dialog controls were not laid out and resized like retail\"");
      return;
    }
    engineerDialogObserved = true;
    CaptureScenarioUiSnapshot(g_pViewMgr->currentTurnEventCode, modal);
    RecordHandledModal("engineer_construction_options");
    if (!RuntimeUiDriver::ActivateControlSemantically(modal, kControlTagCncl)) {
      FailScenario("\"engineer construction dialog cancel control could not be activated\"");
      return;
    }
    if (!engineerDialogObserved) {
      FailScenario("\"engineer construction dialog was not observed\"");
      return;
    }
    Pass();
  }

  TCivUnit* spawnedCivilian;
  short targetHillTile;
  short targetSeaTile;
  short targetSurveyMissTile;
  TCivUnit* farmer;
  short targetFarmerTile;
  short initialFarmerImprovementClass;
  bool orderIssued;
  bool completionIssued;
  bool completionVerified;
  bool surveyMissActionInProgress;
  bool surveyMissOrderIssued;
  bool surveyMissCompletionIssued;
  bool surveyMissCompletionVerified;
  bool farmerActionInProgress;
  bool farmerOrderIssued;
  bool farmerCompletionIssued;
  bool farmerCompletionVerified;
  bool engineerActionIssued;
  bool engineerDialogObserved;
  short initialAnimationFrame;
  int initialAnimationTick;
};

CivilianRecruitmentTestCase g_test;

} // namespace

RuntimeTestCase* CivilianRecruitmentTest() {
  return &g_test;
}
