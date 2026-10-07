#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642490
class TFlagOptionsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TFlagOptionsPicture)
  virtual ~TFlagOptionsPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  TFlagOptionsPicture();
};
ASSERT_SIZE(TFlagOptionsPicture, 0x90);
