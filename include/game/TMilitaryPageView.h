#pragma once

#include "game/TPageView.h"

struct TQuickDrawSurfaceContext;
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065c9c0
class TMilitaryPageView : public TPageView {
public:
  DECLARE_DYNCREATE(TMilitaryPageView)
  virtual ~TMilitaryPageView() override;       // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;               // slot 0x28 0x564bf0
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x5649a0

  TMilitaryPageView();
  void AfterStuffValues();
  void PrepareUnitCache(int bitmapResourceId, int maskResourceId, int depth);

  // TBattleUnitsView::StuffValues loads an image surface here and Close releases it through
  // TDisplayMgr::RemoveGWorld. Other derived constructors clear it.
  TQuickDrawSurfaceContext* primaryUnitAtlas84;
};
