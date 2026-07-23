#pragma once

#include "game/city_ui/TBuildingView.h"
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

  // DoStartup resolves the 23 FourCC tags in g_pTradeSummarySelectionMap into
  // TPictureNumberText controls, then resolves the separate 'labo' and 'powe'
  // controls. UpdateFields reads and writes them through TNumberText's slots 0x79/0x7a.
  TPictureNumberText* commodityValueControlsA0[23];
  TPictureNumberText* laborValueControlFC;
  TPictureNumberText* powerValueControl100;
};

ASSERT_SIZE(TWarehouseView, 0x104);
