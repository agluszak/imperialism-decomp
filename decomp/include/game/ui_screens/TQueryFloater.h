#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006415b8
class TQueryFloater : public TPicture {
public:
  DECLARE_DYNCREATE(TQueryFloater)
  virtual ~TQueryFloater() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  // NOOP: verified empty in original 0x0056e876
  TQueryFloater() {}
};
ASSERT_SIZE(TQueryFloater, 0x90);
