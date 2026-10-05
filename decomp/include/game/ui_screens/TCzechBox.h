#pragma once

#include "compat.h"

#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065fae0
class TCzechBox : public TUpDownPictureButton {
public:
  DECLARE_DYNCREATE(TCzechBox)
  virtual ~TCzechBox() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00571cb0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x571cf0
  virtual void HiliteState(unsigned char fEnabledState,
                           bool fRefreshNow) override; // slot 0x70 0x571d10
  virtual unsigned char IsOn();                                        // slot 0x74 0x571de0
  virtual void SetState(unsigned char isOn, unsigned char refreshNow); // slot 0x75 0x571e00
  virtual void CheckTheLook(unsigned char refreshNow);                 // slot 0x76 0x571d40
  virtual void Toggle(bool refreshNow);                                // slot 0x77 0x571e40
  virtual void ToggleIf(unsigned char expectedState,
                        unsigned char refreshNow); // slot 0x78 0x571e80

  TCzechBox();

  unsigned char isOn94;
  unsigned char padding95[3];
};
ASSERT_SIZE(TCzechBox, 0x98);
