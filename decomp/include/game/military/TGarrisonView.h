#pragma once

#include "compat.h"

#include "game/navy/TMilitaryPageView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064cc70
class TGarrisonView : public TMilitaryPageView {
public:
  DECLARE_DYNCREATE(TGarrisonView)
  virtual ~TGarrisonView() override; // slot 0x01 (scalar deleting destructor)
  virtual void Close() override;     // slot 0x28 0x4a8a20

  TGarrisonView();
  void StuffValues(short tileIndex);

  unsigned char padding88[4];
  short selectedTileIndex;
  unsigned char padding8E[2];
};
ASSERT_SIZE(TGarrisonView, 0x90);
