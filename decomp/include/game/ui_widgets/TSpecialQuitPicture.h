#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00643c78
class TSpecialQuitPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TSpecialQuitPicture)
  virtual ~TSpecialQuitPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005b4a10
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x5b4810
  virtual void Hilite();                        // slot 0x73 0x45acb0

  // NOOP: verified empty in original 0x00458dcb
  TSpecialQuitPicture() {}

  short quitAnimationFrame;
  short padA2;
};
ASSERT_SIZE(TSpecialQuitPicture, 0x94);
