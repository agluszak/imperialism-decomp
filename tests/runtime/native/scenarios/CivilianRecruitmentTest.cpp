#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "probes/CivilianProbe.h"
#include "probes/MapInteractionProbe.h"
#include "probes/MapRenderingProbe.h"
#include "screens/EngineerDialogScreen.h"
#include "screens/ModalScreen.h"
#include "screens/StrategicMapScreen.h"

#include "decomp_types.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/app/TAnimator.h"
#include "game/app/TCivAnimation2.h"
#include "game/city/TCity.h"
#include "game/city/TTown.h"
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
#include "game/gfx/CDib.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/military/TCivUnit.h"
#include "game/military/TMilitaryUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/pointer_representation.h"
#include "game/strategic_terrain.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TCivDescription.h"
#include "game/ui_widgets/TCivToolbar.h"

namespace {

// Civilian work, from the city order that produces a unit to the map pixels its finished work
// changes.
//
// Three civilians in sequence: a prospector (a successful survey, then an unsuccessful one), a
// farmer (a resource improvement whose completion has to change the tile's pixels), and an engineer
// (a depot, reached through the construction dialog that runs its own modal loop).
//
// Most of this file is deliberately not screen work: it reads terrain records, drives real model
// completion, and compares captured pixels. Those are the assertions -- the script is the order
// they happen in.
class CivilianRecruitmentTestCase : public EasyMapScriptScenario {
public:
  CivilianRecruitmentTestCase()
      : spawnedCivilian(0), targetHillTile(-1), targetSeaTile(-1), targetSurveyMissTile(-1),
        farmer(0), targetFarmerTile(-1), initialFarmerImprovementClass(0), engineer(0),
        initialAnimationFrame(0), initialAnimationTick(0) {}

protected:
  void Script() override {
    RT_BEGIN();

    RT_AWAIT(StrategicMapScreen::IsCurrent(), kObserveUiStateChanged);

    // --- A prospector, and the cursors that say where it may work. ---
    RT_DO("recruit a prospector", RecruitProspector());
    RT_AWAIT(spawnedCivilian->unitOrder == kUnitOrderIdle, kObserveUiStateChanged);
    RT_DO("cycle the civilian legend's targets", VerifyLegendCameraCycling());
    RT_DO("verify the prospector's cursors and order click", VerifyCursorsAndOrderClick());

    RT_DO("let the animator run", PulseAnimator());
    RT_DO("verify the ordered prospector stays visible", VerifyOrderedProspectorIsInspectable());
    RT_DO("complete the survey", CompleteProspectorOrder());
    RT_DO("verify the survey mark reached the renderer", VerifyCompletedSurveyMark());

    // --- The same prospector on a tile with nothing to find. ---
    RT_DO("order a survey that will find nothing", IssueUnsuccessfulSurvey());
    RT_DO("complete the unsuccessful survey", CompleteUnsuccessfulSurvey());
    RT_DO("verify the miss mark reached the renderer", VerifyUnsuccessfulSurveyMark());

    // --- A farmer, whose finished improvement must change the tile. ---
    RT_DO("recruit a farmer and order an improvement", OrderFarmerImprovement());
    // An improvement takes as many turns as the order says; the original scenario re-entered its
    // completion phase until the farmer went idle, and the loop is that, said out loud.
    while (farmer->unitOrder != kUnitOrderIdle) {
      RT_DO("advance the farmer's improvement", AdvanceFarmerImprovement());
    }
    RT_DO("verify the improvement changed the tile", VerifyFarmerImprovementVisual());

    // --- An engineer, through the construction dialog and on to a depot. ---
    RT_DO("open the engineer's construction dialog", OpenEngineerConstructionDialog());
    // The dialog ran its own modal loop and the pre-armed cancel closed it; a modal still up means
    // that loop never unwound.
    RT_REQUIRE(!ModalScreen::AnyPresent());
    RT_DO("build the depot and check the province chain", VerifyDepotAndMilitaryChain());

    CaptureCurrentScreenSnapshot();
    RT_REQUIRE(HasScenarioUiSnapshot());
    RT_PASS();

    RT_END();
  }

private:
  enum { kGlobalMapTileCount = 0x1950 };
  enum { kProvinceRecordCount = 0x180 };
  // Every turn-event cursor resource, which the classifier indexes into.
  enum { kTurnEventCursorCount = 0x36 };
  // The cursors this scenario expects the classifier to choose: prospectable land, and water.
  enum { kProspectableCursor = 1001, kProhibitedWaterCursor = 1008 };
  // What the map reports for a tile the selected civilian is already working.
  enum { kOrderedTileReportCursor = 0x3f3 };

  short ActiveNation() const {
    return g_pSimMgr->GetActiveNationId();
  }

  TGreatPower* Player() const {
    return g_apNationStates[ActiveNation()];
  }

  TMapUberPicture* MapView() const {
    return StrategicMap().View();
  }

  TMapDialog* MapDialog() const {
    return StrategicMap().Dialog();
  }

  RuntimeActionResult PulseAnimator() {
    // The ordered civilian's sprite only advances while the animator gets idle time.
    g_pUiAnimator->DoIdle(1);
    return RuntimeActionResult::Success();
  }

  // --- Producing a civilian through a real city order. ---

  RuntimeActionResult ProduceCivilian(short civilianKind, TCivUnit** outCivilian) {
    TGreatPower* nation = Player();
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the active nation has no city to recruit from");
    }
    const int previousCount = CivilianProbe::CivilianCount(ActiveNation());
    const int previousUnitId = g_pSimMgr->field_64;
    TUnitOrder recruitOrder;
    recruitOrder.IUnitOrder(nation->city, civilianKind, 0, 0, -1, 0, 0, kLowSkillWorkforceMode, 0);
    recruitOrder.quantity = 1;
    recruitOrder.Produce();

    if (CivilianProbe::CivilianCount(ActiveNation()) != previousCount + 1) {
      return RuntimeActionResult::Failure(
          "civilian production did not register exactly one recruit");
    }
    if (g_pSimMgr->field_64 != previousUnitId + 1) {
      return RuntimeActionResult::Failure(
          "civilian production did not allocate exactly one persistent unit id");
    }
    *outCivilian = CivilianProbe::CivilianWithPersistentId(ActiveNation(), g_pSimMgr->field_64);
    if (*outCivilian == 0) {
      return RuntimeActionResult::Failure("the produced civilian is not in the nation's roster");
    }
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult RecruitProspector() {
    RuntimeActionResult produced =
        ProduceCivilian(EncodeCivilianUnitKind(kCivilianUnitProspector), &spawnedCivilian);
    if (!produced.Succeeded()) {
      return produced;
    }
    if (spawnedCivilian->tileIndex06 < 0 || spawnedCivilian->tileIndex06 >= kGlobalMapTileCount) {
      return RuntimeActionResult::Failure(
          "the newly allocated civilian has an invalid strategic-map tile");
    }
    const signed char ownerTag =
        g_pGlobalMapState->terrainStateTable[spawnedCivilian->tileIndex06].ownerNationTag04;
    if (ownerTag < 0 || ownerTag >= kTerrainTypeDescriptorTableCount ||
        g_apTerrainTypeDescriptorTable[ownerTag] == 0) {
      return RuntimeActionResult::Failure(
          "the recruited civilian's tile has no terrain-owner descriptor");
    }
    if (spawnedCivilian->ownerNationSlot18 != ActiveNation()) {
      return RuntimeActionResult::Failure(
          "the produced civilian is not owned by the active nation");
    }
    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(spawnedCivilian, 1);

    targetHillTile = FindProspectorTarget(kStrategicTerrainHills, true);
    targetSeaTile = FindProspectorTarget(kStrategicTerrainWater, false);
    if (targetHillTile == -1 || targetSeaTile == -1) {
      CString detail;
      detail.Format("prospector samples missing: eligible hill=%d prohibited sea=%d",
                    targetHillTile, targetSeaTile);
      return RuntimeActionResult::Failure(detail);
    }
    if (MapView() == 0) {
      return RuntimeActionResult::Failure("the strategic map is not showing");
    }
    MapView()->CenterOn(targetHillTile);
    return RuntimeActionResult::Success();
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

  // --- Cursors and the order click. ---

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

  RuntimeActionResult VerifyCursorForTile(TMapDialog* mapDialog, short targetTile,
                                          short expectedToken, CPoint* outPoint) {
    MapView()->CenterOn(targetTile);

    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);

    short band = 0;
    if (!FindVisiblePointForTile(mapDialog, targetTile, outPoint, &band)) {
      return RuntimeActionResult::Failure(
          "the centred prospector target has no visible map hit point");
    }

    const unsigned short classifiedToken =
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(targetTile,
                                                                                       band);
    if (classifiedToken != expectedToken) {
      CString detail;
      detail.Format("the cursor classifier chose %d for tile %d, not the expected %d",
                    static_cast<int>(classifiedToken), static_cast<int>(targetTile),
                    static_cast<int>(expectedToken));
      return RuntimeActionResult::Failure(detail);
    }

    mapDialog->cursorId4e = 0xffff;
    if (!MapInteractionProbe::HoverAtLocalPoint(mapDialog, *outPoint)) {
      return RuntimeActionResult::Failure("the map dialog has no host window to hover over");
    }
    if (mapDialog->cursorId4e != expectedToken) {
      return RuntimeActionResult::Failure("a native hover did not apply the classified cursor");
    }

    HCURSOR expectedCursor =
        g_pViewMgr->turnEventCursors[expectedToken - TViewMgr::kCursorResourceIdBase];
    if (!MapRenderingProbe::CursorIsActiveAndVisible(expectedCursor)) {
      return RuntimeActionResult::Failure("the classified cursor is not visibly active");
    }
    return RuntimeActionResult::Success();
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

  TAnimation* RenderAndResolveOrderedProspectorAnimation() {
    TMapDialog* mapDialog = MapDialog();
    MapView()->CenterOn(targetHillTile);
    {
      PrimarySurfaceGuard primarySurface;
      CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
      mapDialog->Draw(&mapBounds);
    }
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

  // Clicking a legend slot walks the camera through that profile's target tiles in order and wraps
  // back to the first once they are exhausted.
  RuntimeActionResult VerifyLegendCameraCycling() {
    TMapDialog* mapDialog = MapDialog();
    TCivDescription* description = StrategicMap().CivilianLegend();
    if (mapDialog == 0) {
      return RuntimeActionResult::Failure("the strategic map has no map dialog");
    }
    if (description == 0 ||
        description->selectedCivilianClass != EncodeCivilianUnitKind(kCivilianUnitProspector)) {
      return RuntimeActionResult::Failure("the selected prospector has no civilian legend control");
    }

    PrimarySurfaceGuard primarySurface;
    CRect descriptionBounds(0, 0, description->frameWidth34, description->frameHeight38);
    description->Draw(&descriptionBounds);

    int selectedColumn = -1;
    short selectedProfile = -1;
    int candidateCount = 0;
    const int visibleColumnCount =
        g_pTechMgr->orderCapRows277[ActiveNation()].techStatusByTechId[4] == 2 ? 5 : 2;
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
      CString detail;
      detail.Format("legend target mismatch: column=%d profile=%d candidates=%d shown=%d "
                    "counter=%d owner=%d",
                    selectedColumn, selectedProfile, candidateCount,
                    selectedColumn < 0 ? -1 : description->targetTileCountsBySlot[selectedColumn],
                    selectedProfile < 0 ? -1
                                        : g_awCivilianLegendSelectionCountsBySlot[selectedProfile],
                    description->ownerNationId);
      return RuntimeActionResult::Failure(detail);
    }

    short targetTiles[kGlobalMapTileCount];
    CPoint targetOrigins[kGlobalMapTileCount];
    CollectProspectorLegendTargets(description->ownerNationId, selectedProfile, targetTiles);
    for (int candidateOrdinal = 0; candidateOrdinal < candidateCount; ++candidateOrdinal) {
      mapDialog->CenterOn(targetTiles[candidateOrdinal]);
      targetOrigins[candidateOrdinal] = mapDialog->viewportOrigin;
    }
    mapDialog->CenterOn(targetSeaTile);

    int centeredClickCount = 0;
    bool observedCounterWrap = false;
    const int clickLimit = candidateCount + 3;
    for (int clickOrdinal = 0; clickOrdinal < clickLimit && centeredClickCount < candidateCount + 1;
         ++clickOrdinal) {
      unsigned short counterBefore = g_awCivilianLegendSelectionCountsBySlot[selectedProfile];
      CPoint originBefore = mapDialog->viewportOrigin;
      if (!description->ActivateLegendSlot(selectedProfile)) {
        return RuntimeActionResult::Failure("a legend slot lost its semantic action");
      }
      unsigned short counterAfter = g_awCivilianLegendSelectionCountsBySlot[selectedProfile];
      if (counterBefore < candidateCount) {
        if (counterAfter != counterBefore + 1 ||
            !SameMapOrigin(mapDialog->viewportOrigin, targetOrigins[counterBefore])) {
          return RuntimeActionResult::Failure(
              "a legend click did not centre its indexed retail target");
        }
        ++centeredClickCount;
      } else {
        if (counterAfter != counterBefore % candidateCount ||
            !SameMapOrigin(mapDialog->viewportOrigin, originBefore)) {
          return RuntimeActionResult::Failure(
              "legend exhaustion did not apply the retail counter reset");
        }
        observedCounterWrap = true;
      }
    }
    if (!observedCounterWrap || centeredClickCount != candidateCount + 1) {
      return RuntimeActionResult::Failure(
          "legend selection did not cycle through the first tile again");
    }
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult VerifyCursorsAndOrderClick() {
    for (int index = 0; index < kTurnEventCursorCount; ++index) {
      if (g_pViewMgr->turnEventCursors[index] == 0) {
        CString detail;
        detail.Format("turn-event cursor resource ~C%d did not load", index + 1000);
        return RuntimeActionResult::Failure(detail);
      }
    }

    TMapDialog* mapDialog = MapDialog();
    if (mapDialog == 0) {
      return RuntimeActionResult::Failure("the strategic map has no map dialog");
    }
    if (mapDialog->nativeWindow50 == 0 || mapDialog->nativeWindow50->m_hWnd == 0) {
      return RuntimeActionResult::Failure("the strategic map has no native mouse-routing host");
    }

    PrimarySurfaceGuard primarySurface;

    CPoint hillPoint;
    CPoint seaPoint;
    // Water first: classifying a prohibited tile must not disturb the selection.
    RuntimeActionResult seaCursor =
        VerifyCursorForTile(mapDialog, targetSeaTile, kProhibitedWaterCursor, &seaPoint);
    if (!seaCursor.Succeeded()) {
      return seaCursor;
    }
    if (spawnedCivilian->unitOrder != kUnitOrderIdle) {
      return RuntimeActionResult::Failure(
          "verifying the water cursor changed the selected prospector's order");
    }
    RuntimeActionResult hillCursor =
        VerifyCursorForTile(mapDialog, targetHillTile, kProspectableCursor, &hillPoint);
    if (!hillCursor.Succeeded()) {
      return hillCursor;
    }

    if (spawnedCivilian->unitOrder != kUnitOrderIdle ||
        spawnedCivilian->tileIndex06 == targetHillTile) {
      CString detail;
      detail.Format("the prospector was not idle before the click: order=%d tile=%d target=%d",
                    spawnedCivilian->unitOrder, spawnedCivilian->tileIndex06, targetHillTile);
      return RuntimeActionResult::Failure(detail);
    }
    short hillBand = 0;
    if (!FindVisiblePointForTile(mapDialog, targetHillTile, &hillPoint, &hillBand)) {
      return RuntimeActionResult::Failure(
          "the strategic-map target has no semantic interaction band");
    }
    mapDialog->HandleMapClickByInteractionMode(targetHillTile, hillBand);

    if (spawnedCivilian->unitOrder != kUnitOrderProspect ||
        spawnedCivilian->tileIndex06 != targetHillTile) {
      CString detail;
      detail.Format("the prospector click did not order the survey: order=%d tile=%d target=%d",
                    spawnedCivilian->unitOrder, spawnedCivilian->tileIndex06, targetHillTile);
      return RuntimeActionResult::Failure(detail);
    }

    TCivUnit* tileCivilian =
        g_pGlobalMapState->GetTileUnitEntryByOwner(targetHillTile, ActiveNation());
    TAnimation* animation = RenderAndResolveOrderedProspectorAnimation();
    const bool isCivilianSprite = CivilianProbe::IsCivilianSpriteAnimation(animation);
    const bool hasFramePixels = animation != 0 && AnimationFrameBufferHasPixels(animation);
    if (tileCivilian != spawnedCivilian || !isCivilianSprite || !hasFramePixels) {
      CString detail;
      detail.Format("the ordered prospector's animation is invalid: tile=%d animation=%d sprite=%d "
                    "pixels=%d",
                    tileCivilian == spawnedCivilian, animation != 0, isCivilianSprite,
                    hasFramePixels);
      return RuntimeActionResult::Failure(detail);
    }

    initialAnimationFrame = animation->frameIndex;
    initialAnimationTick = animation->ticksSinceFrameChange;
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult VerifyOrderedProspectorIsInspectable() {
    TMapDialog* mapDialog = MapDialog();
    if (mapDialog == 0) {
      return RuntimeActionResult::Failure(
          "the strategic map disappeared while the order was active");
    }

    TAnimation* animation = RenderAndResolveOrderedProspectorAnimation();
    TCivUnit* tileCivilian =
        g_pGlobalMapState->GetTileUnitEntryByOwner(targetHillTile, ActiveNation());
    const unsigned short reportCursor =
        g_pSelectedCivilianOrderState->ResolveCivilianTileSelectionOrReportActionCode(
            targetHillTile, 0);
    const bool animationAdvanced =
        animation != 0 && (animation->frameIndex != initialAnimationFrame ||
                           animation->ticksSinceFrameChange != initialAnimationTick);
    const bool hasFramePixels = animation != 0 && AnimationFrameBufferHasPixels(animation);
    if (tileCivilian != spawnedCivilian || animation == 0 || !animationAdvanced ||
        reportCursor != kOrderedTileReportCursor || !hasFramePixels) {
      CString detail;
      detail.Format("ordered-prospector validation failed: tile=%d animation=%d advanced=%d "
                    "frame=%d/%d tick=%d/%d cursor=%d pixels=%d",
                    tileCivilian == spawnedCivilian, animation != 0, animationAdvanced,
                    animation == 0 ? -1 : animation->frameIndex, initialAnimationFrame,
                    animation == 0 ? -1 : animation->ticksSinceFrameChange, initialAnimationTick,
                    static_cast<int>(reportCursor), hasFramePixels);
      return RuntimeActionResult::Failure(detail);
    }
    if (!MapRenderingProbe::HoverMovementRestoresPreviousTiles(mapDialog, targetHillTile)) {
      return RuntimeActionResult::Failure(
          "hovering left stale map pixels outside the current tile");
    }
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult CompleteProspectorOrder() {
    spawnedCivilian->TickCivWorkOrderCountdownAndComplete();
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult VerifyCompletedSurveyMark() {
    TMapDialog* mapDialog = MapDialog();
    if (mapDialog == 0) {
      return RuntimeActionResult::Failure(
          "the strategic map disappeared before the completion was rendered");
    }

    const int activeNation = ActiveNation();
    const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[targetHillTile];
    if (spawnedCivilian->unitOrder != kUnitOrderIdle || spawnedCivilian->remainingTurns24 > 0 ||
        (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) == 0 ||
        spawnedCivilian->completionMarker26 != 0x232f ||
        g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(targetHillTile) == 0) {
      CString detail;
      detail.Format("prospector completion mismatch: order=%d remaining=%d survey=%d marker=%d "
                    "candidate=%d",
                    spawnedCivilian->unitOrder, spawnedCivilian->remainingTurns24,
                    (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) != 0,
                    spawnedCivilian->completionMarker26,
                    g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(targetHillTile));
      return RuntimeActionResult::Failure(detail);
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
      RedrawTileThroughRenderer(targetHillTile);
      if (WasStrategicMapResourceTileObservedForRuntimeTest()) {
        resourceIconRendered = true;
        break;
      }
    }
    if (!observableResource || !resourceIconRendered) {
      return RuntimeActionResult::Failure(
          "the completed survey did not reach the strategic resource renderer");
    }
    return RuntimeActionResult::Success();
  }

  // Centre, invalidate and draw one tile through the map's own renderer, which is what the
  // observation hooks above watch for.
  void RedrawTileThroughRenderer(short tile) {
    TMapDialog* mapDialog = MapDialog();
    MapView()->CenterOn(tile);
    MapView()->RedrawTile(tile);
    PrimarySurfaceGuard primarySurface;
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
  }

  bool IsProspectableResource(signed char resourceType) {
    return resourceType == kResourceCoal || resourceType == kResourceIron ||
           resourceType == kResourceOil || resourceType == kResourceGems ||
           resourceType == kResourceGold;
  }

  RuntimeActionResult IssueUnsuccessfulSurvey() {
    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(spawnedCivilian, 1);
    const int activeNation = ActiveNation();
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
      CString detail;
      detail.Format("no unsuccessful prospecting tile: eligible=%d nonmineral=%d undiscovered=%d "
                    "orderable=%d",
                    eligibleCount, nonMineralCount, undiscoveredCount, orderableCount);
      return RuntimeActionResult::Failure(detail);
    }

    TMapDialog* mapDialog = MapDialog();
    if (mapDialog == 0) {
      return RuntimeActionResult::Failure(
          "the strategic map disappeared before the unsuccessful survey");
    }
    PrimarySurfaceGuard primarySurface;
    MapView()->CenterOn(targetSurveyMissTile);
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
    CPoint targetPoint;
    short targetBand;
    if (!FindVisiblePointForTile(mapDialog, targetSurveyMissTile, &targetPoint, &targetBand) ||
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(
            targetSurveyMissTile, targetBand) != kProspectableCursor) {
      return RuntimeActionResult::Failure(
          "the unsuccessful prospecting tile lost its retail cursor route");
    }
    mapDialog->HandleMapClickByInteractionMode(targetSurveyMissTile, targetBand);
    if (spawnedCivilian->unitOrder != kUnitOrderProspect ||
        spawnedCivilian->tileIndex06 != targetSurveyMissTile) {
      return RuntimeActionResult::Failure(
          "the non-mineral tile did not receive the retail prospecting order");
    }
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult CompleteUnsuccessfulSurvey() {
    g_pUiAnimator->DoIdle(1);
    spawnedCivilian->TickCivWorkOrderCountdownAndComplete();
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult VerifyUnsuccessfulSurveyMark() {
    const int activeNation = ActiveNation();
    const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[targetSurveyMissTile];
    if (MapDialog() == 0 || spawnedCivilian->unitOrder != kUnitOrderIdle ||
        spawnedCivilian->remainingTurns24 > 0 ||
        (terrain.pendingDevelopmentFlag0d & (1 << activeNation)) == 0 ||
        IsProspectableResource(terrain.resourceTypeByEdge[0]) ||
        g_pGlobalMapState->CheckTileProspectingDiscoveryCandidate(targetSurveyMissTile) != 0) {
      return RuntimeActionResult::Failure(
          "the unsuccessful survey did not produce the retail surveyed state");
    }

    ObserveStrategicMapSurveyMissTileForRuntimeTest(targetSurveyMissTile);
    RedrawTileThroughRenderer(targetSurveyMissTile);
    if (!WasStrategicMapSurveyMissTileObservedForRuntimeTest()) {
      return RuntimeActionResult::Failure(
          "the surveyed non-mineral tile did not reach the retail miss-mark blit");
    }
    return RuntimeActionResult::Success();
  }

  // --- The farmer. ---

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

  RuntimeActionResult OrderFarmerImprovement() {
    RuntimeActionResult produced =
        ProduceCivilian(EncodeCivilianUnitKind(kCivilianUnitFarmer), &farmer);
    if (!produced.Succeeded()) {
      return produced;
    }
    if (farmer->GetCivilianUnitKind() != kCivilianUnitFarmer ||
        farmer->unitOrder != kUnitOrderIdle) {
      return RuntimeActionResult::Failure("farmer production did not yield an idle farmer");
    }

    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(farmer, 0);
    const short nationSlot = farmer->ownerNationSlot18;
    short workableTile = -1;
    short moveTile = -1;
    short prohibitedTile = -1;
    int predicateMismatches = 0;
    // Sweep the whole map: the retail predicate and the map's own reach marking have to agree
    // everywhere, not just on the tile this scenario goes on to use.
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
    if (predicateMismatches != 0 || workableTile == -1 || moveTile == -1 || prohibitedTile == -1 ||
        occupiedAction != 2) {
      CString detail;
      detail.Format("farmer selection mismatch: predicates=%d workable=%d move=%d prohibited=%d "
                    "occupied=%d",
                    predicateMismatches, workableTile, moveTile, prohibitedTile, occupiedAction);
      return RuntimeActionResult::Failure(detail);
    }

    if (g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(workableTile, 0) != 9 ||
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(
            workableTile, 0) != g_civilianTileOrderCursorTokenTable[9]) {
      return RuntimeActionResult::Failure(
          "the workable tile did not retain the retail action and cursor route");
    }

    targetFarmerTile = workableTile;
    initialFarmerImprovementClass = static_cast<short>(
        g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(targetFarmerTile, 0));

    TMapDialog* mapDialog = MapDialog();
    if (mapDialog == 0) {
      return RuntimeActionResult::Failure(
          "the strategic map disappeared before the improvement order");
    }
    PrimarySurfaceGuard primarySurface;
    MapView()->CenterOn(targetFarmerTile);
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);
    CPoint targetPoint;
    short targetBand;
    if (!FindVisiblePointForTile(mapDialog, targetFarmerTile, &targetPoint, &targetBand) ||
        g_pSelectedCivilianOrderState->LookupCivilianTileOrderCursorTokenByActionIndex(
            targetFarmerTile, targetBand) != g_civilianTileOrderCursorTokenTable[9]) {
      return RuntimeActionResult::Failure("the improvement tile lost its retail cursor route");
    }
    mapDialog->HandleMapClickByInteractionMode(targetFarmerTile, targetBand);
    if (farmer->unitOrder != kUnitOrderDevelopResource || farmer->tileIndex06 != targetFarmerTile) {
      return RuntimeActionResult::Failure(
          "the farmer click did not queue the retail resource improvement order");
    }
    return RuntimeActionResult::Success();
  }

  // One turn of the farmer's order. The animator gets its idle tick too, so the map keeps animating
  // the working civilian while the order runs down.
  RuntimeActionResult AdvanceFarmerImprovement() {
    g_pUiAnimator->DoIdle(1);
    farmer->TickCivWorkOrderCountdownAndComplete();
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult VerifyFarmerImprovementVisual() {
    TMapDialog* mapDialog = MapDialog();
    const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[targetFarmerTile];
    const short improvementClass = static_cast<short>(
        g_pGlobalMapState->GetTileCivilianWorkOrderCostClassNibble(targetFarmerTile, 0));
    const short resourceType = terrain.resourceTypeByEdge[0];
    if (mapDialog == 0 || farmer->unitOrder != kUnitOrderIdle || farmer->remainingTurns24 > 0 ||
        improvementClass != initialFarmerImprovementClass + 1 || resourceType < 0 ||
        g_anResourceTypeRequiredOrderType[resourceType] != farmer->orderType) {
      return RuntimeActionResult::Failure(
          "the farmer's completion did not advance the retail improvement state");
    }

    ObserveStrategicMapImprovementTileForRuntimeTest(targetFarmerTile, resourceType,
                                                     improvementClass);
    RedrawTileThroughRenderer(targetFarmerTile);
    if (!WasStrategicMapImprovementTileObservedForRuntimeTest() ||
        !MapRenderingProbe::DevelopmentClassChangesTilePixels(
            mapDialog, targetFarmerTile, static_cast<unsigned char>(initialFarmerImprovementClass),
            static_cast<unsigned char>(improvementClass))) {
      return RuntimeActionResult::Failure(
          "the completed improvement did not change the rendered tile pixels");
    }
    return RuntimeActionResult::Success();
  }

  // --- The engineer. ---

  RuntimeActionResult OpenEngineerConstructionDialog() {
    RuntimeActionResult produced =
        ProduceCivilian(EncodeCivilianUnitKind(kCivilianUnitEngineer), &engineer);
    if (!produced.Succeeded()) {
      return produced;
    }
    if (engineer->GetCivilianUnitKind() != kCivilianUnitEngineer ||
        engineer->unitOrder != kUnitOrderIdle) {
      return RuntimeActionResult::Failure("engineer production did not yield an idle engineer");
    }

    TGreatPower* nation = Player();
    char* connectedTiles = 0;
    nation->BuildTransportLinkedInfluenceMap(&connectedTiles);
    short engineerTile = -1;
    int engineerAction = 0;
    for (short tile = 0; tile < kGlobalMapTileCount; ++tile) {
      const TTerrainStateRecord& terrain = g_pGlobalMapState->terrainStateTable[tile];
      if (terrain.ownerNationTag04 != engineer->ownerNationSlot18 || connectedTiles[tile] == 0) {
        continue;
      }
      engineer->MoveTo(tile);
      g_pSelectedCivilianOrderState->SetActiveCivilianSelection(engineer, 1);
      engineerAction = g_pSelectedCivilianOrderState->ResolveCivilianTileOrderActionCode(tile, 0);
      if (engineerAction == 4) {
        engineerTile = tile;
        break;
      }
    }
    delete[] connectedTiles;
    if (engineerAction != 4) {
      return RuntimeActionResult::Failure(
          "no transport-connected tile resolved to the engineer build action");
    }

    TMapDialog* mapDialog = MapDialog();
    if (mapDialog == 0) {
      return RuntimeActionResult::Failure(
          "the strategic map disappeared before the engineer build action");
    }
    MapView()->CenterOn(engineerTile);

    // The click below does not return until the dialog it opens is answered, so the answer is
    // queued first.
    RuntimeActionResult armed = EngineerDialogScreen::ArmCancel();
    if (!armed.Succeeded()) {
      return armed;
    }
    mapDialog->HandleMapClickByInteractionMode(engineerTile, 0);
    RecordHandledModal("engineer_construction_options");
    return RuntimeActionResult::Success();
  }

  RuntimeActionResult VerifyDepotAndMilitaryChain() {
    const short depotTile = engineer->tileIndex06;
    const short ownerNation = engineer->ownerNationSlot18;
    TGreatPower* nation = g_apNationStates[ownerNation];
    const int oldTownCount = nation->townMarkerList->GetCount();
    const int expectedTownCount =
        oldTownCount + ((g_pGlobalMapState->terrainStateTable[depotTile].activeFlags1c & 4) == 0);
    engineer->SetOrders(kUnitOrderBuildDepot, depotTile);
    while (engineer->remainingTurns24 > 0) {
      engineer->TickCivWorkOrderCountdownAndComplete();
    }

    TTown* depot = g_pGlobalMapState->FindTownMarkerForTileByOwnerNation(depotTile);
    if (engineer->unitOrder != kUnitOrderIdle || depot == 0 || depot->activeFlag == 0 ||
        depot->transportLinked == 0 || nation->townMarkerList->GetCount() != expectedTownCount ||
        (g_pGlobalMapState->terrainStateTable[depotTile].activeFlags1c & 0x10) == 0 ||
        engineer->completionMarker26 != 0x232a) {
      CString detail;
      detail.Format("connected depot mismatch: order=%d town=%d active=%d linked=%d count=%d/%d "
                    "flags=%d marker=%d",
                    engineer->unitOrder, depot != 0, depot != 0 ? depot->activeFlag : -1,
                    depot != 0 ? depot->transportLinked : -1, nation->townMarkerList->GetCount(),
                    expectedTownCount,
                    g_pGlobalMapState->terrainStateTable[depotTile].activeFlags1c,
                    engineer->completionMarker26);
      return RuntimeActionResult::Failure(detail);
    }

    // Two equal-priority units in one province: the newer one takes the chain head, and detaching
    // it must not leave the province pointing at freed memory.
    short province = -1;
    for (short candidate = 0; candidate < kProvinceRecordCount; ++candidate) {
      if (g_pGlobalMapState->cityScoreTable[candidate].stationedUnitChain98 == 0) {
        province = candidate;
        break;
      }
    }
    if (province == -1) {
      return RuntimeActionResult::Failure(
          "the random map has no empty province for the stationed-unit chain check");
    }

    TMilitaryUnit* olderUnit = new TMilitaryUnit();
    olderUnit->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitMinutemen), province, ownerNation,
                             0);
    TMilitaryUnit* newerUnit = new TMilitaryUnit();
    newerUnit->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitMinutemen), province, ownerNation,
                             0);
    Province& depotProvince = g_pGlobalMapState->cityScoreTable[province];
    if (depotProvince.stationedUnitChain98 != newerUnit || newerUnit->previousAtLocation10 != 0 ||
        newerUnit->nextAtLocation14 != olderUnit || olderUnit->previousAtLocation10 != newerUnit) {
      return RuntimeActionResult::Failure(
          "an equal-priority military unit did not become the retail chain head");
    }

    olderUnit->DetachUnitOrderFromOwnerAndReset();
    olderUnit->Free();
    if (depotProvince.stationedUnitChain98 != newerUnit || newerUnit->previousAtLocation10 != 0 ||
        newerUnit->nextAtLocation14 != 0) {
      return RuntimeActionResult::Failure(
          "detaching the former military head left a dangling province chain");
    }
    newerUnit->DetachUnitOrderFromOwnerAndReset();
    newerUnit->Free();
    return RuntimeActionResult::Success();
  }

  TCivUnit* spawnedCivilian;
  short targetHillTile;
  short targetSeaTile;
  short targetSurveyMissTile;
  TCivUnit* farmer;
  short targetFarmerTile;
  short initialFarmerImprovementClass;
  TCivUnit* engineer;
  short initialAnimationFrame;
  int initialAnimationTick;
};

} // namespace

RUNTIME_TEST_FACTORY(CivilianRecruitmentTestCase, CivilianRecruitmentTest)
