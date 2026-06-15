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
  unsigned short fieldShort76;
  unsigned char stateByte78;
  unsigned char stateByte79;
  unsigned char stateByte7a;
  unsigned char pad7b;
  int stateDword7c;
  unsigned char stateByte80;
  char pad81[0x03];

  TSoundPlayer();
  CRuntimeClass* GetRuntimeClass() const override;

  // TSoundPlayer overrides of TEventHandler slots.
  void ReleaseRuntimeSelectionOwnerAndDestroyObject() override; // 0x07 -> 0x5e51d0
  char CanHandleCityDialogActionFalse(int action) override;     // 0x13 -> 0x593400

  // TSoundPlayer-introduced slots (0x25+), matching ApplicationUiRootController fork layout.
  virtual void InitializeSoundSubsystemAndAllocateChannelLists(int param_1); // 0x25 -> 0x5e4e70
  virtual unsigned char ReturnConstantTrue_SoundPredicate();                 // 0x26 -> 0x5e4f60
  virtual unsigned char ReturnConstantFalse_SoundPredicate(int a, int b);    // 0x27 -> 0x5e4fb0
  virtual void RequestDirectSoundInitIfAllowed();                            // 0x28 -> 0x5e4f80
  virtual void ClearDirectSoundInitPendingAndResetState();                   // 0x29 -> 0x5e4fd0
};

TSoundPlayer* CreateTSoundPlayerInstance(void);
