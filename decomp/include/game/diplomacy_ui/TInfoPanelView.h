#pragma once

#include "game/app/TPanelView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0063fe60
class TInfoPanelView : public TPanelView {
public:
  DECLARE_DYNCREATE(TInfoPanelView)
  virtual ~TInfoPanelView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004fad60
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4fa010
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4fa190
  virtual void Setup() override;                // slot 0x68 0x4facc0
  virtual void SetInfoCountry(short countryId); // slot 0x69 0x4fae00
  short countryInfoCategoryIndices64[4];        // 0x64
  int selectedOverlayMode6C;                    // 0x6c

  TInfoPanelView();
};

ASSERT_SIZE(TInfoPanelView, 0x70);
