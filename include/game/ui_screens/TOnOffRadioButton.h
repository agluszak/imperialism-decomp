#pragma once

#include "compat.h"

#include "game/ui_screens/TPictureButton.h"
#include "game/mfc.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#endif

// VTABLE: IMPERIALISM 0x0065f8a8
class TOnOffRadioButton : public TPictureButton {
public:
  DECLARE_DYNCREATE(TOnOffRadioButton)
  virtual ~TOnOffRadioButton() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00571a80
  using TPictureButton::SetState;
  virtual void SetState(unsigned char on,
                        unsigned char drawImmediate); // slot 0x74 0x571b20

  TOnOffRadioButton();

  // Original object size is 0x98 (CRuntimeClass m_nObjectSize). The ctor (0x5719f0)
  // zeroes a single byte at +0x94 (the sibling TCzechBox models the same slot as its
  // on/off state byte); the remaining three bytes are layout padding.
  unsigned char field94;
  unsigned char padding95[3];
};
ASSERT_SIZE(TOnOffRadioButton, 0x98);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
