#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00643818
class TMultiMessagePicture : public TPicture {
public:
  DECLARE_DYNCREATE(TMultiMessagePicture)
  virtual ~TMultiMessagePicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;

  TMultiMessagePicture();
};
ASSERT_SIZE(TMultiMessagePicture, 0x90);
