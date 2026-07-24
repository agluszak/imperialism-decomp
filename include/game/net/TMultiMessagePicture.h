#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00643818
class TMultiMessagePicture : public TPicture {
public:
  DECLARE_DYNCREATE(TMultiMessagePicture)
  virtual ~TMultiMessagePicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0054ecc0

  TMultiMessagePicture();
};
ASSERT_SIZE(TMultiMessagePicture, 0x90);
