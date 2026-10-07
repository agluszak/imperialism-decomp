#pragma once

#include "compat.h"

#include "game/city_ui/TBuildingView.h"
#include "game/ui_tags_city.h"
#include "game/mfc.h"

struct TQuickDrawSurfaceContext;

// VTABLE: IMPERIALISM 0x00651b30
class TShipyardView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TShipyardView)
  virtual ~TShipyardView() override;
  virtual void Free() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void DoStartup() override;
  virtual void UpdateFields() override;
  virtual void SetStats(short shipType);
  virtual void SetStats(TView* sourceControl);
  virtual void GetCostString(CString* output, short actionIndex);
  virtual void SetShip(short shipType);

  TShipyardView();
  void LoadShipGWorld();

  short selectedRequirementRow;
  short selectedStatsRow;
  short buildQueueSlotValues[8];         // AKA requirementResourceTypeByRow
  int unresolvedZero;                    // only DoStartup's zero write is confirmed
  TQuickDrawSurfaceContext* iconSurface; // LoadBitmapResourceSurfaceAndRestoreQuickDrawContext
  short commoditySpriteIds[4];
  short commodityRequiredAmounts[4];
};
ASSERT_SIZE(TShipyardView, 0xcc);
