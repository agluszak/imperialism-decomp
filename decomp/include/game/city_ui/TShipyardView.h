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
  virtual ~TShipyardView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;      // slot 0x07 0x4c8340
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                   // slot 0x0f 0x004c8ac0
  virtual void Draw(RECT* rectBuffer) override;                   // slot 0x44 0x4c9150
  virtual void DoStartup() override;                              // slot 0x75 0x4c8390
  virtual void UpdateFields() override;                           // slot 0x76 0x4c8a50
  virtual void SetStats(short shipType);                          // slot 0x7a 0x4c9a60
  virtual void SetStats(TView* sourceControl);                    // slot 0x79 0x4c9d20
  virtual void GetCostString(CString* output, short actionIndex); // slot 0x7b 0x4c97c0
  virtual void SetShip(short shipType);                           // slot 0x7c 0x4c8d70

  TShipyardView();
  void LoadShipGWorld(); // 0x004c8a20

  short selectedRequirementRow; // +0xa0
  short selectedStatsRow;
  short buildQueueSlotValues[8]; // +0xa4..+0xb3 -- AKA requirementResourceTypeByRow
  int unresolvedZero;            // +0xb4, only DoStartup's zero write is confirmed
  TQuickDrawSurfaceContext*
      iconSurface; // +0xb8 -- LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0x264f)
  short commoditySpriteIds[4];       // +0xbc
  short commodityRequiredAmounts[4]; // +0xc4
};
ASSERT_SIZE(TShipyardView, 0xcc);
