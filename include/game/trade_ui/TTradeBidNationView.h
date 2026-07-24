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

  // Original object size is 0x64 (CRuntimeClass m_nObjectSize); the source class ended
  // at 0x60. InstallViews writes the line's trade-category slot to +0x60 and the nation
  // slot to +0x62; Draw currently consumes the latter.
  short categorySlot60;
  short nationSlot62;
};
ASSERT_SIZE(TTradeBidNationView, 0x64);
