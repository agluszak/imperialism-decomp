#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642490
class TFlagOptionsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TFlagOptionsPicture)
  virtual ~TFlagOptionsPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0056b2b0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x56b640

  TFlagOptionsPicture();
};
ASSERT_SIZE(TFlagOptionsPicture, 0x90);
