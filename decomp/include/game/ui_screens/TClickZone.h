#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660180
class TClickZone : public TControl {
public:
  DECLARE_DYNCREATE(TClickZone)
  virtual ~TClickZone() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x572490
  virtual void Hilite();                               // slot 0x71 0x5723d0

  TClickZone();

  short clickSoundId84;
  unsigned char padding86[2];
};
ASSERT_SIZE(TClickZone, 0x88);
