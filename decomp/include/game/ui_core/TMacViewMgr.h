
#pragma once

#include "game/map_domain_types.h"
#include "game/nation_domain_types.h"
#include "compat.h"

#include "game/app/TObject.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/city_ui/StrategicMapCallbackRecord.h"

#include "game/mfc.h"

class TStream;
class TBitmapResourceLoader;
class TView;
class TCity;
class TBuildingView;
class TCityProductionView;
class TTradeCluster;
struct TQuickDrawSurfaceContext;
struct TBitmapSurfaceNode;

// Strategic map view / render system (singleton g_pMacViewMgr @ 0x006a21a8).
// VTABLE: IMPERIALISM 0x00658660
class TMacViewMgr : public TObject {
public:
  DECLARE_DYNCREATE(TMacViewMgr)
  virtual ~TMacViewMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  virtual void CreateCommodityIconsGWorld();
  virtual void LoadStrategicMapUnitIconAtlas750();
  virtual void LoadStrategicMapUnitOverlayAtlas751();
  virtual void CreateMiniFlagsGWorld();
  virtual void LoadStrategicMapMarkerAtlas1372();
  virtual void GetTradeCluster(TTradeCluster* orderSource, short orderSlot, short nationSlot);
  virtual void ShowTradeCluster(TView* view, short orderSlot, short nationIndex);
  virtual void ShowTransportEntry(short resourceSlot, short nationIndex, TView* hostView);
  virtual TView* MakeBookDialog(int dialogId);
  // RET 0x8 = 2 dwords; body waits on this->activeCityProductionView, args vestigial.
  virtual void SelectCitySite(int unusedArg1, int unusedArg2);
  virtual TBuildingView* RestoreBuildingWindowAtSavedPosition(short buildingSlot, TCity* city,
                                                              bool closeAfterOpen,
                                                              bool isEmbeddedPage,
                                                              TCityProductionView* productionView,
                                                              short savedX, short savedY);
  virtual TBuildingView* OpenBuildingWindow(short buildingSlot, TCity* city, bool closeAfterOpen,
                                            bool isEmbeddedPage,
                                            TCityProductionView* productionView);
  virtual void OpenConstructionWindow(short buildingSlot, TCity* city,
                                      TCityProductionView* productionView);
  virtual void UpdateCityScreen();
  virtual void CloseBuilding(short buildingSlot);
  virtual void CloseCityView();
  virtual void CreateMapArtStorage();
  virtual void RefreshGoldControl();
  virtual void GenerateMiniMap();
  virtual void GenerateRegions();
  virtual void RegenerateCountryRegions();
  virtual void CopyMapIcon(TBitmapSurfaceNode** dstSurface, short iconIndex, short x, short y);
  virtual void DrawStrategicMapUnitIcon(TBitmapSurfaceNode** pDstSurface, short nIconVariant,
                                        short nDstX, short nYShift);
  virtual void CopyDevelopmentIcon(TBitmapSurfaceNode** pDstSurface, ushort wOverlayIconId,
                                   short nVariantRow, short nDstX, short nYShift);
  virtual void FastDrawPicture(TBitmapResourceLoader** loaderHandle, unsigned char* destinationBits,
                               short destinationStride);
  virtual void MakeCountryRegion(int country);
  virtual unsigned char PtInCountry(CPoint* point, short regionIndex);
  virtual void SetCountryRgn(RgnHandle sourceRegion, short slotIndex);
  virtual RgnHandle GetCountryRegion(short index);

  TCityProductionView* activeCityProductionView;
  RgnHandle countryRegions[kNationSlotCount];
  RgnHandle tileStateSlots[kProvinceCount];
  int padding664;
  TQuickDrawSurfaceContext* terrainTileWorld;
  TQuickDrawSurfaceContext* improvementTileWorld;
  TQuickDrawSurfaceContext* miniMapWorld;
  TQuickDrawSurfaceContext* commodityIconWorld;
  TQuickDrawSurfaceContext* unitIconAtlas;
  TQuickDrawSurfaceContext* unitOverlayAtlas;
  TQuickDrawSurfaceContext* flagWorld;
  TQuickDrawSurfaceContext* markerWorld;
  TQuickDrawSurfaceContext* gaugeWorld;
  TQuickDrawSurfaceContext* nationFleetWorld;
  TQuickDrawSurfaceContext* nationUnitWorld;
  TQuickDrawSurfaceContext* tileOverlayStripWorlds[8];
  TQuickDrawSurfaceContext* stackBadgeWorld;
  TQuickDrawSurfaceContext* mapArtWorld;
  StrategicMapCallbackRecord strategicTileMasks[36];
  int fieldD7c;
  int fieldD80;

  TMacViewMgr();
  void IMacViewMgr();
  void BlitActivityFrame(TBitmapSurfaceNode** destinationSurface, short overlayFrameIndex,
                         short destinationX, short destinationYFromBottom);
  void CreateIngotsGWorlds();
  void ReloadCityArt();
  void CreateIndexedGWorlds();
  void ReloadMapArtAtlases();
};
ASSERT_SIZE(TMacViewMgr, 0xd84);
