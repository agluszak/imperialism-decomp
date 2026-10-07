#pragma once

#include "compat.h"

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006428f0
class TGamePreferencesPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TGamePreferencesPicture)
  virtual ~TGamePreferencesPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  TGamePreferencesPicture();

  int originalSoundVolumePercent; // restored when the preferences dialog is cancelled
};
ASSERT_SIZE(TGamePreferencesPicture, 0x94);
