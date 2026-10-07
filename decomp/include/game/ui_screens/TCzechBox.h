#pragma once

#include "compat.h"

#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065fae0
class TCzechBox : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TCzechBox)
  virtual ~TCzechBox() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void HiliteState(unsigned char fEnabledState, bool fRefreshNow) override;
  virtual unsigned char IsOn();
  virtual void SetState(unsigned char isOn, unsigned char refreshNow);
  virtual void CheckTheLook(unsigned char refreshNow);
  virtual void Toggle(bool refreshNow);
  virtual void ToggleIf(unsigned char expectedState, unsigned char refreshNow);

  TCzechBox();

  unsigned char isOn;
  unsigned char padding95[3];
};
ASSERT_SIZE(TCzechBox, 0x98);
