#pragma once

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066af08
class TTechItemView : public TView {
public:
  DECLARE_DYNCREATE(TTechItemView)
  virtual ~TTechItemView() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005b1e20

  int nationSlot60; // +0x60 — TTechMgr capability-matrix row (hedged name)
  int techId64;     // +0x64 — read as short for string offsets, as int for the cost table

  // NOOP: verified empty in original 0x005b1283
  TTechItemView() {}

  void ITechItemView(TView* panel, int* offsetLayout, int* sizeLayout, int nationSlot, int techId);
};

ASSERT_SIZE(TTechItemView, 0x68);
