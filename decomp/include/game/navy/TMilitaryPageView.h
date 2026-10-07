#pragma once

#include "compat.h"

#include "game/ui_screens/TPageView.h"

struct TQuickDrawSurfaceContext;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065c9c0
class TMilitaryPageView : public TPageView {
public:
  DECLARE_DYNCREATE(TMilitaryPageView)
  virtual ~TMilitaryPageView() override;
  virtual void Close() override;
  virtual void DoPostCreate(int arg) override;

  TMilitaryPageView();
  void AfterStuffValues();
  void PrepareUnitCache(int bitmapResourceId, int maskResourceId, int depth);

  TQuickDrawSurfaceContext* primaryUnitAtlas;
};
ASSERT_SIZE(TMilitaryPageView, 0x88);
