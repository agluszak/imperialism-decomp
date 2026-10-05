#pragma once

#include "compat.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TDiplomacyMapView;

// VTABLE: IMPERIALISM 0x00655db8
class TPanelView : public TView {
public:
  DECLARE_DYNCREATE(TPanelView)
  virtual ~TPanelView() override;              // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x4f79e0
  virtual void Setup();                        // slot 0x68 0x430550
  TDiplomacyMapView* diplomacyMapView; // +0x60

  TPanelView() : TView(), diplomacyMapView(0) {}
};

ASSERT_SIZE(TPanelView, 0x64);
