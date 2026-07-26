#pragma once

#include "compat.h"

#include "game/battle_report_records.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064e5e0
class TItemBoyView : public TView {
public:
  DECLARE_DYNCREATE(TItemBoyView)
  virtual ~TItemBoyView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4af9f0

  // NOOP: verified empty in original 0x004af943 (no standalone TItemBoyView::TItemBoyView body exists: CreateObject 0x004af910 inlines this default ctor, calling the TView base ctor directly at that site)
  TItemBoyView() {}

  // Draws `header` at a fixed origin, then blits a horizontal row of item-kind icons
  // (icon strip cached at *(g_pStrategicMapViewSystem + 0x674) + 4, distinct from the
  // Army/Navy boy views' +0x694 strip) using this->frameWidth34 (inherited from
  // TView) and the context's item count to lay out each icon's width. Non-virtual
  // helper called only from Draw; real name unrecovered (Ghidra's
  // provisional name for 0x4afb60 follows its usual scalar-deleting-destructor
  // template, but this is a plain paint helper, not a destructor -- verified from
  // the raw listing).
  void DrawItemHeaderAndIconRows(CString* header);

  BattleReportDetailRecord* battleDetail60; // +0x60
};
ASSERT_SIZE(TItemBoyView, 0x64);
