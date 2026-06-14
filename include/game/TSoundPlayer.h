#pragma once

#include "game/TEventHandler.h"

struct CRuntimeClass;

// Sound subsystem controller — a TEventHandler fork (same construction/teardown pattern as
// ApplicationUiRootController), not a TView/TControl descendant. Construct only runs the
// TEventHandler header defaults (InitializeUiResourceEntryBaseHeaderDefaults in the
// original), then installs vtable 0x668a60. Size 0x84.
// VTABLE: IMPERIALISM 0x668a60
class TSoundPlayer : public TEventHandler {
public:
  unsigned char directSoundInitOkAt20; // 0x20 — set by InitializeSoundSubsystem
  char pad21[0x4b];
  void* runtimePeerAt6c;
  void* runtimePeerAt70;
  unsigned short fieldShort74;
  char pad76[0x02];
  unsigned char stateByte78;
  unsigned char stateByte79;
  unsigned char stateByte7a;
  unsigned char pad7b;
  int stateDword7c;
  char pad80[0x04];

  TSoundPlayer();
  CRuntimeClass* GetRuntimeClass() override;

  // TSoundPlayer-introduced slots (0x25+), matching ApplicationUiRootController fork layout.
  virtual void SoundPlayerSlot25_Provisional();
  virtual void SoundPlayerSlot26_Provisional();
  virtual void SoundPlayerSlot27_Provisional();
  virtual void SoundPlayerSlot28_Provisional(); // body used by InitializeSoundSubsystem +0xa0
  virtual void SoundPlayerSlot29_Provisional(); // body used by InitializeSoundSubsystem +0xa4
};

TSoundPlayer* CreateTSoundPlayerInstance(void);
