#include "RuntimeScenario.h"

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

class CivilianRecruitmentTestCase : public RuntimeScenario {
public:
  CivilianRecruitmentTestCase() : spawnedCivilian(0), targetMountainTile(-1), selectionTicks(0) {}

  const char* Name() const override {
    return "civilian_recruitment_selection";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    spawnedCivilian = 0;
    selectionTicks = 0;
    EnterScenarioStep("recruiting_civilian", "produce_and_select_recruited_civilian");
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
    if (spawnedCivilian == 0) {
      RecruitCivilian();
      return;
    }

    ++selectionTicks;
    if (selectionTicks < 20) {
      RequestScenarioTick();
      return;
    }
    VerifyProspectorMountainCursor();
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
    TUnitOrder recruitOrder;
    recruitOrder.IUnitOrder(nation->city, EncodeCivilianUnitKind(kCivilianUnitProspector), 0, 0, -1,
                            0, 0, kLowSkillWorkforceMode, 0);
    recruitOrder.quantityField04 = 1;
    recruitOrder.Produce();

    if (nation->trackedObjectList->GetCount() != oldCount + 1) {
      FailScenario("\"civilian production did not register exactly one recruit\"");
      return;
    }
    spawnedCivilian = static_cast<TCivUnit*>(
        nation->trackedObjectList->GetEntryByOrdinal(nation->trackedObjectList->GetCount()));
    if (spawnedCivilian == 0 || spawnedCivilian->tileIndex06 < 0 ||
        spawnedCivilian->tileIndex06 >= kGlobalMapTileCount) {
      FailScenario("\"recruited civilian has an invalid strategic-map tile\"");
      return;
    }

    signed char ownerTag =
        g_pGlobalMapState->terrainStateTable[spawnedCivilian->tileIndex06].ownerNationTag04;
    if (ownerTag < 0 || ownerTag >= kTerrainTypeDescriptorTableCount ||
        g_apTerrainTypeDescriptorTable[ownerTag] == 0) {
      FailScenario("\"recruited civilian tile has no terrain-owner descriptor\"");
      return;
    }

    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(spawnedCivilian, 1);
    targetMountainTile = FindUnoccupiedMountainTile();
    if (targetMountainTile == -1) {
      FailScenario("\"random map has no unoccupied mountain for cursor verification\"");
      return;
    }
    // Arrange the precise action context under test. The real selection dispatcher seeds
    // this byte as an eligibility mask based on the prospector's location and technology;
    // clearing one actual mountain makes it a valid survey target without bypassing the
    // map hover classifier or cursor-table lookup.
    g_pGlobalMapState->terrainStateTable[targetMountainTile].recruitSearchVisited0e = 0;
    TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
    mapView->CenterOn(targetMountainTile);
    EnterScenarioStep("waiting_after_civilian_selection",
                      "selected_prospector_and_centered_unvisited_mountain");
    RequestScenarioTick();
  }

  short FindUnoccupiedMountainTile() {
    for (short tile = 0; tile < kGlobalMapTileCount; ++tile) {
      const TTerrainStateRecordView& terrain = g_pGlobalMapState->terrainStateTable[tile];
      if (terrain.GetTerrainKind() != kStrategicTerrainMountain ||
          terrain.firstCivilianOrder20 != 0 || terrain.tileActionState16 != -1 ||
          tile % 0x6c == 0 || tile % 0x6c == 0x6b) {
        continue;
      }
      return tile;
    }
    return -1;
  }

  void VerifyProspectorMountainCursor() {
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
    CRect mapBounds(0, 0, mapDialog->frameWidth34, mapDialog->frameHeight38);
    mapDialog->Draw(&mapBounds);

    CPoint cursorPoint;
    bool foundPoint = false;
    for (int y = 1; y < mapDialog->frameHeight38 && !foundPoint; y += 2) {
      for (int x = 1; x < mapDialog->frameWidth34; x += 2) {
        short column;
        short row;
        short band;
        CPoint candidate(x, y);
        mapDialog->ConvertPoint(candidate, column, row, band);
        short tile = static_cast<short>(ComputeStridedRecordAddress6C(column, row));
        if (tile == targetMountainTile) {
          cursorPoint = candidate;
          foundPoint = true;
          break;
        }
      }
    }
    if (!foundPoint) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"centered mountain has no visible eye-cursor hit point\"");
      return;
    }

    if (mapDialog->nativeWindow50 == 0 || mapDialog->nativeWindow50->m_hWnd == 0) {
      SetGWorld(savedSurface, savedSurfaceFlags);
      FailScenario("\"strategic map has no native mouse-routing host\"");
      return;
    }

    mapDialog->activeRegionBand72 = -1;
    mapDialog->cursorId4e = 0xffff;
    CPoint hostPoint(cursorPoint.x + mapDialog->absoluteX, cursorPoint.y + mapDialog->absoluteY);
    SendMessageA(mapDialog->nativeWindow50->m_hWnd, WM_MOUSEMOVE, 0,
                 MAKELPARAM(hostPoint.x, hostPoint.y));
    SetGWorld(savedSurface, savedSurfaceFlags);

    HCURSOR expectedCursor = g_pUiRuntimeContext->turnEventCursors[1];
    if (mapDialog->cursorId4e != 1001 || expectedCursor == 0 || GetCursor() != expectedCursor ||
        !CursorDrawsVisiblePixels(expectedCursor)) {
      FailScenario("\"prospector hover over mountain did not activate the eye cursor\"");
      return;
    }
    Pass();
  }

  TCivUnit* spawnedCivilian;
  short targetMountainTile;
  unsigned long selectionTicks;
};

CivilianRecruitmentTestCase g_test;

} // namespace

RuntimeTestCase* CivilianRecruitmentTest() {
  return &g_test;
}
