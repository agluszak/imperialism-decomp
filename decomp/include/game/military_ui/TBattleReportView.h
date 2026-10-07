#pragma once

#include "game/diplomacy_ui/TDiplomacyMapView.h"

class TAnimator;
class TIdleMeAnimation;
struct MapContextActionRecord;

// VTABLE: IMPERIALISM 0x0063efa8
class TBattleReportView : public TDiplomacyMapView {
public:
  DECLARE_DYNCREATE(TBattleReportView)
  ~TBattleReportView() override; // slot 0x01 scalar deleting dtor

  void Free() override; // slot 0x07 0x4ad560
  void DoEvent(int commandId, TEventHandler* sourceHandler,
               TEvent* event) override; // slot 0x0f 0x4ad7a0
  bool DoIdle(int action) override;     // slot 0x13 0x4ad5a0
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override; // slot 0x35
  void DoPostCreate(int arg) override;                                                 // slot 0x37
  void Draw(RECT* rectBuffer) override;                                                // slot 0x44
  void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                      CPoint origin) override; // slot 0x47 0x4adcb0

  bool ShouldDisplay(MapContextActionRecord* record) const;
  MapContextActionRecord* GetBattleAt(const CPoint& point) const;
  void RefreshMapContextSelectionPanelAndInfoLabels(MapContextActionRecord* mapContextRecord);

  void RenderMapContextActionMarkers(RECT* rectBuffer);

  TBattleReportView() : TDiplomacyMapView(), selectedReportIndex(1), transientRegistryObject(0) {}

private:
  int selectedReportIndex;
  TIdleMeAnimation* transientRegistryObject;
};

ASSERT_SIZE(TBattleReportView, 0x24d0);
