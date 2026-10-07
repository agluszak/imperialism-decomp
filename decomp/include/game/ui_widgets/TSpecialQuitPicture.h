#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00643c78
class TSpecialQuitPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TSpecialQuitPicture)
  virtual ~TSpecialQuitPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void Hilite();

  // NOOP: verified empty in original 0x00458dcb
  TSpecialQuitPicture() {}

  short quitAnimationFrame;
  short padA2;
};
ASSERT_SIZE(TSpecialQuitPicture, 0x94);
