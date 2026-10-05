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
                           bool drawImmediate) override;                // slot 0x70 0x4aa310
  virtual unsigned char IsOn();                                         // slot 0x71 0x4aa340
  virtual void SetState(unsigned char on, unsigned char drawImmediate); // slot 0x72 0x4aa360
  virtual void CheckTheLook(unsigned char drawImmediate);               // slot 0x73 0x4aa030
  virtual void Toggle(bool drawImmediate);                              // slot 0x74 0x4aa3a0
  virtual void ToggleIf(unsigned char expectedState,
                        unsigned char drawImmediate); // slot 0x75 0x4aa3e0
  virtual void DrawImmediate();                       // slot 0x76 0x4aa430
  unsigned char isOn84;
  unsigned char pad85[3];
  int iconStripHorizontalOffset;
  int checkedFrameOffsetApplied8c;
  TQuickDrawSurfaceContext* surfaceContext;

  // NOOP: verified empty in original 0x004a9f57 (no standalone TArmyCheckBox::TArmyCheckBox body exists: CreateObject 0x004a9f20 inlines this default ctor, calling the TControl base ctor directly at that site)
  TArmyCheckBox() {}

  TArmyCheckBox(TView* panel, int* offsetLayout, int* sizeLayout, int unused1, int unused2,
                TQuickDrawSurfaceContext* surfaceContext90Value,
                int iconStripHorizontalOffsetValue);
};

ASSERT_SIZE(TArmyCheckBox, 0x94);
