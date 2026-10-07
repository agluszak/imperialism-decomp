#pragma once

#include "game/diplomacy_ui/TDiplomacyMapView.h"

class TAnimator;
class TIdleMeAnimation;
struct MapContextActionRecord;

// VTABLE: IMPERIALISM 0x0063efa8
class TBattleReportView : public TDiplomacyMapView {
public:
  DECLARE_DYNCREATE(TBattleReportView)
  ~TBattleReportView() override;

  void Free() override;
  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  bool DoIdle(int action) override;
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override;
  void DoPostCreate(int arg) override;
  void Draw(RECT* rectBuffer) override;
  void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;

  bool ShouldDisplay(MapContextActionRecord* record) const;
  MapContextActionRecord* GetBattleAt(const CPoint& point) const;
  void DisplayBattle(MapContextActionRecord* mapContextRecord);

  void DrawBattleNuggets(RECT* rectBuffer);

  TBattleReportView() : selectedReportIndex(1), transientRegistryObject(0) {}

private:
  int selectedReportIndex;
  TIdleMeAnimation* transientRegistryObject;
};

ASSERT_SIZE(TBattleReportView, 0x24d0);
