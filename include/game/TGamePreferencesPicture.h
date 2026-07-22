#pragma once

#include "game/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006428f0
class TGamePreferencesPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TGamePreferencesPicture)
  virtual ~TGamePreferencesPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x0056ae10
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x56a5b0

  TGamePreferencesPicture();

  int originalSoundVolumePercent; // 0x90, restored when the preferences dialog is cancelled
};
