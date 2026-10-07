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
  virtual ~TWarehouseView() override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void DoStartup() override;
  virtual void UpdateFields() override;

  TWarehouseView();

  TPictureNumberText* commodityValueControls[23];
  TPictureNumberText* laborValueControl;
  TPictureNumberText* powerValueControl;
};

ASSERT_SIZE(TWarehouseView, 0x104);
