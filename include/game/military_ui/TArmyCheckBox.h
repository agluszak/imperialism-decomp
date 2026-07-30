#pragma once

#include "compat.h"
#include "game/ui_core/TControl.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064cec0
class TArmyCheckBox : public TControl {
public:
  DECLARE_DYNCREATE(TArmyCheckBox)
  virtual ~TArmyCheckBox() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x004aa280
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x4aa2f0
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x4aa100
  virtual void HiliteState(unsigned char hilited,
                           unsigned char drawImmediate) override;       // slot 0x70 0x4aa310
  virtual unsigned char IsOn();                                         // slot 0x71 0x4aa340
  virtual void SetState(unsigned char on, unsigned char drawImmediate); // slot 0x72 0x4aa360
  virtual void CheckTheLook(unsigned char drawImmediate);               // slot 0x73 0x4aa030
  virtual void Toggle(unsigned char drawImmediate);                     // slot 0x74 0x4aa3a0
  virtual void ToggleIf(unsigned char expectedState,
                        unsigned char drawImmediate); // slot 0x75 0x4aa3e0
  virtual void DrawImmediate();                       // slot 0x76 0x4aa430
  // TControl's own slice ends at 0x84 (RTTI oracle: sizeof(TControl) == 0x84);
  // sizeof(TArmyCheckBox) == 0x94, adding one 0x10-byte region. The real ctor
  // (0x4a9fe0) only ever writes field88/field90 (its 6th/7th real stack params --
  // Ghidra's own signature undercounts the real param count as 5). The trailing
  // region contains the checkbox state and the currently applied glyph offset.
  unsigned char isOn84;
  unsigned char pad85[3];
  // Horizontal pixel offset added to the paint rect's left/right when blitting from
  // surfaceContext90 (Draw, 0x4aa100). The army-unit upgrade path selects the two-frame
  // pair for the unit's order type; CheckTheLook then selects the unchecked/checked frame
  // within that pair.
  int iconStripHorizontalOffset88;
  int checkedFrameOffsetApplied8c;
  // A second QuickDraw surface (icon strip) this checkbox blits its check-glyph from,
  // read at +0x4 (blit surface) and +0x20 (backing CDib, for the negative-height DIB
  // vertical-flip adjustment) -- the exact same TQuickDrawSurfaceContext shape used by
  // g_pActiveQuickDrawSurfaceContext elsewhere in Draw.
  TQuickDrawSurfaceContext* surfaceContext90;

  // NOOP: verified empty in original 0x004a9f57 (no standalone TArmyCheckBox::TArmyCheckBox body exists: CreateObject 0x004a9f20 inlines this default ctor, calling the TControl base ctor directly at that site)
  TArmyCheckBox() {}

  // Real ctor (0x4a9fe0): forwards panel/offsetLayout/sizeLayout to the already-ported
  // TView::InitializeUiResourceEntryFrameAndParent (resourceContext=null,
  // layoutParam6/7=4, attachFlag=0), then stores its own two trailing args into
  // surfaceContext90/iconStripHorizontalOffset88. unused1/unused2 (the 4th/5th real stack
  // params) are never
  // read by this ctor.
  TArmyCheckBox(TView* panel, int* offsetLayout, int* sizeLayout, int unused1, int unused2,
                TQuickDrawSurfaceContext* surfaceContext90Value,
                int iconStripHorizontalOffsetValue);
};

ASSERT_SIZE(TArmyCheckBox, 0x94);
