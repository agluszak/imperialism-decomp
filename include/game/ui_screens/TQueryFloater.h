#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006415b8
class TQueryFloater : public TPicture {
public:
  DECLARE_DYNCREATE(TQueryFloater)
  virtual ~TQueryFloater() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0056ea20
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x56e8e0

  TQueryFloater();
};
ASSERT_SIZE(TQueryFloater, 0x90);
