#pragma once

#include "compat.h"

#include "game/ui_core/TControl.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00660180
class TClickZone : public TControl {
public:
  DECLARE_DYNCREATE(TClickZone)
  virtual ~TClickZone() override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void Hilite();

  TClickZone();

  short clickSoundId;
  unsigned char padding86[2];
};
ASSERT_SIZE(TClickZone, 0x88);
