#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e530
class TTradeBidNationView : public TView {
public:
  DECLARE_DYNCREATE(TTradeBidNationView)
  virtual ~TTradeBidNationView() override;
  virtual void Draw(RECT* rectBuffer) override;

  // NOOP: verified empty in original 0x005bdb73
  TTradeBidNationView() {}

  short categorySlot;
  short nationSlot;

  void ITradeBidNationView(TView* panel, int* offsetLayout, int* sizeLayout, short nation,
                           short category);
};
ASSERT_SIZE(TTradeBidNationView, 0x64);
