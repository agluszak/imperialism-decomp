#pragma once

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063fe60
class TInfoPanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TInfoPanelView)
  virtual ~TInfoPanelView() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Setup() override;
  virtual void SetInfoCountry(short countryId);
  short countryInfoCategoryIndices[4];
  int selectedOverlayMode;

  TInfoPanelView();
};

ASSERT_SIZE(TInfoPanelView, 0x70);
