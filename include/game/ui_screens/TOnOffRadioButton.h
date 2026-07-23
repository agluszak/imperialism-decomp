#pragma once

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

  // Original object size is 0x98 (CRuntimeClass m_nObjectSize); the source class ended at 0x94. Trailing 4 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field94;
};

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
