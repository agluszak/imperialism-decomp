#pragma once

#include "compat.h"
#include "game/ui_core/TControl.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064cec0
class TArmyCheckBox : public TControl {
public:
  DECLARE_DYNCREATE(TArmyCheckBox)
  virtual ~TArmyCheckBox() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void HiliteState(unsigned char hilited, bool drawImmediate) override;
  virtual unsigned char IsOn();
  virtual void SetState(unsigned char on, unsigned char drawImmediate);
  virtual void CheckTheLook(unsigned char drawImmediate);
  virtual void Toggle(bool drawImmediate);
  virtual void ToggleIf(unsigned char expectedState, unsigned char drawImmediate);
  virtual void DrawImmediate();
  unsigned char isOn;
  int iconStripHorizontalOffset;
  int checkedFrameOffsetApplied;
  TQuickDrawSurfaceContext* surfaceContext;

  // NOOP: verified empty in original 0x004a9f57
  TArmyCheckBox() {}

  TArmyCheckBox(TView* panel, int* offsetLayout, int* sizeLayout, int unused1, int unused2,
                TQuickDrawSurfaceContext* surfaceContext90Value,
                int iconStripHorizontalOffsetValue);
};

ASSERT_SIZE(TArmyCheckBox, 0x94);
