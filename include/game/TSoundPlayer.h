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
  unsigned char directSoundInitOkAt20;      // 0x20 — set by InitializeSoundSubsystem
  unsigned char directSoundInitPendingAt21; // 0x21 — set by RequestDirectSoundInitIfAllowed
  char pad22[0x4a];
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
  // Slot 0x25 (Init 0x5e4e70) and slots 0x28/0x29 (Request/Clear 0x5e4f80/0x5e4fd0) still
  // provisional: Init allocates two inline list nodes (needs the list class recovered) and
  // Request/Clear dispatch to the unmodeled sound-device global at 0x6a60c0.
  virtual void SoundPlayerSlot25_Provisional();                           // 0x25 -> 0x5e4e70
  virtual unsigned char ReturnConstantTrue_SoundPredicate();              // 0x26 -> 0x5e4f60
  virtual unsigned char ReturnConstantFalse_SoundPredicate(int a, int b); // 0x27 -> 0x5e4fb0
  virtual void SoundPlayerSlot28_Provisional();                           // 0x28 -> 0x5e4f80
  virtual void SoundPlayerSlot29_Provisional();                           // 0x29 -> 0x5e4fd0
};

TSoundPlayer* CreateTSoundPlayerInstance(void);
