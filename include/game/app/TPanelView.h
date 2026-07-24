#pragma once

#include "compat.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"

class TDiplomacyMapView;

// VTABLE: IMPERIALISM 0x00655db8
class TPanelView : public TView {
public:
  DECLARE_DYNCREATE(TPanelView)
  virtual ~TPanelView() override;              // slot 0x01 (scalar deleting destructor)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x4f79e0
  virtual void Setup();                        // slot 0x68 0x430550
  // TView's slice ends at 0x60; RTTI oracle confirms sizeof(TPanelView) == 0x64. The one
  // own field is zeroed at construction. TPanelView's ctor has no standalone
  // out-of-line address -- the compiler always inlines it (e.g. into CreateObject at
  // 0x4f78e0 and into TOffersPanelView's ctor) -- so it carries no // FUNCTION marker.
  TDiplomacyMapView* diplomacyMapView60; // +0x60

  // In-class inline: the original has no out-of-line TPanelView::TPanelView -- every
  // derived constructor absorbs it (e.g. 0x00430320 is CALL TView::TView, then
  // [esi+0x60] = 0, then the derived vptr store). An out-of-line definition in the .cpp
  // cannot be inlined across TUs and pessimizes every subclass ctor into a call.
  TPanelView() : TView(), diplomacyMapView60(0) {}
};

ASSERT_SIZE(TPanelView, 0x64);
