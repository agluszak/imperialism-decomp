#pragma once

#include "compat.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TDiplomacyMapView;

// VTABLE: IMPERIALISM 0x00655db8
class TPanelView : public TView {
public:
  DECLARE_DYNCREATE(TPanelView)
  virtual ~TPanelView() override;
  virtual void DoPostCreate(int arg) override;
  virtual void Setup();
  TDiplomacyMapView* diplomacyMapView;

  TPanelView() : TView(), diplomacyMapView(0) {}
};

ASSERT_SIZE(TPanelView, 0x64);
