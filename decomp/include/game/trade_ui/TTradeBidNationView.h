#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066e530
class TTradeBidNationView : public TView {
public:
  DECLARE_DYNCREATE(TTradeBidNationView)
  virtual ~TTradeBidNationView() override;      // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5bdc20

  // NOOP: verified empty in original 0x005bdb73 (no standalone TTradeBidNationView::TTradeBidNationView body exists: CreateObject 0x005bdb40 inlines this default ctor, calling the TView base ctor directly at that site)
  TTradeBidNationView() {}

  short categorySlot;
  short nationSlot;

  void ITradeBidNationView(TView* panel, int* offsetLayout, int* sizeLayout,
                           short nation, short category);
};
ASSERT_SIZE(TTradeBidNationView, 0x64);
