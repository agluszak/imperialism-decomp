#pragma once

#include "game/city_ui/TBuildingView.h"
#include "game/resource_manifest_tags.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TPictureNumberText;

// VTABLE: IMPERIALISM 0x006516a0
class TWarehouseView : public TBuildingView {
public:
  DECLARE_DYNCREATE(TWarehouseView)
  virtual ~TWarehouseView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x4c7330
  virtual void DoStartup() override;                   // slot 0x75 0x4c7360
  virtual void UpdateFields() override;                // slot 0x76 0x4c7d90

  TWarehouseView();

  TPictureNumberText* commodityValueControls[23];
  TPictureNumberText* laborValueControl;
  TPictureNumberText* powerValueControl;
};

ASSERT_SIZE(TWarehouseView, 0x104);
