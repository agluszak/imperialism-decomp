#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642d58
class TCreditsPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TCreditsPicture)
  virtual ~TCreditsPicture() override;

  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void Hilite();

  TCreditsPicture();
};
ASSERT_SIZE(TCreditsPicture, 0x90);
