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

  // Inline in the original: the TTechItemLine factory (0x5b1160) expands it as the
  // TView base ctor call plus the vptr store.
  // NOOP: verified empty in original 0x005b1283 (no standalone TTechItemView::TTechItemView body exists: CreateObject 0x005b1250 inlines this default ctor, calling the TView base ctor directly at that site)
  TTechItemView() {}

  // Second-phase init (single caller: the TTechItemLine factory at 0x5b1160): builds the
  // tech-item row UI — 'desc' picture button, title (name + newline + year) and
  // description TDeluxeText children, and one of three status variants (completion date /
  // 'purc' buy button / missing-prerequisites line). 0x5b12e0, __thiscall, RET 0x14.
  void ITechItemView(TView* panel, int* offsetLayout, int* sizeLayout, int nationSlot, int techId);
};

ASSERT_SIZE(TTechItemView, 0x68);
