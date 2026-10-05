#pragma once

#include "compat.h"

#include "game/ui_core/TEventHandler.h"
#include "game/city_ui/TLongintList.h"
#include "game/core/CString.h"

struct CRuntimeClass;

// Sound subsystem controller (TEventHandler descendant). Size 0x84.
// VTABLE: IMPERIALISM 0x668a60
class TSoundPlayer : public TEventHandler {
public:
  unsigned char directSoundInitOk; // 0x20 — set by InitializeSoundSubsystem
  bool directSoundInitPending;     // 0x21 — set by RequestDirectSoundInitIfAllowed
  char pad22[0x4a];
  TLongintList* audioCuePool;
  TLongintList* remainingRandomAudioCues;
  unsigned short activeAudioCueId;
  unsigned short pendingAudioCueId;
  bool cdAudioPlaybackActive;
  unsigned char unused79; // ctor-only write; field-xrefs show no reader
  unsigned char unused7A; // ctor-only write; field-xrefs show no reader
  unsigned char padding7B;
  unsigned int fadeStartTick16;
  bool clearCuePoolsAfterFade;
  char pad81[0x03];

  TSoundPlayer();
  // FUNCTION: IMPERIALISM 0x005933e0
  ~TSoundPlayer() override {} // 0x5933e0 (slot 0x01 scalar deleting dtor 0x5933b0)
  DECLARE_DYNCREATE(TSoundPlayer)
  void Free() override;             // 0x07 -> 0x5e51d0
  char DoIdle(int action) override; // 0x13 -> 0x593400

  // TSoundPlayer-introduced slots (0x25+).
  virtual void ISoundPlayer(int idleFrequency);            // 0x25 -> 0x5e4e70
  virtual unsigned char DefaultSoundCapabilityPredicate(); // 0x26 -> 0x5e4f60
  virtual unsigned char DefaultSoundCompatibilityPredicate(int unusedArg1,
                                                           int unusedArg2); // 0x27 -> 0x5e4fb0
  virtual void RequestDirectSoundInitIfAllowed();                           // 0x28 -> 0x5e4f80
  virtual void ClearDirectSoundInitPendingAndResetState();                  // 0x29 -> 0x5e4fd0
  virtual void StopAllSoundChannels();                                      // 0x2a -> 0x5e4ff0
  virtual void SetMasterVolumeFromPercent(short percent);                        // 0x2b -> 0x5e5020
  virtual void PriorityOverride(short currentPriority, short requestedPriority); // 0x2c -> 0x5e50a0
  virtual int
  UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(short sfxToken, int unusedArg2 = 0,
                                                       int unusedArg3 = 1,
                                                       int unusedArg4 = 1); // 0x2d -> 0x5e50c0
  virtual int PlaySoundEffect(short sfxToken, int forwardedArg2 = 0,
                              int forwardedArg3 = 1); // 0x2e -> 0x5e5140
  virtual int PlaySoundAsynchronously(short soundId, short channel,
                                      short priority);                              // 0x2f 0x5e5170
  virtual int PlaySoundSynchronously(short soundId, short channel, short priority); // 0x30 0x5e5190
  virtual int PlayAiffFile(CString fileName, short channel, short priority);        // 0x31 0x5e51b0

  char FadeCD();

  void StopMusic(bool fadeOut); // 0x593c10

  void StartDeferredAudioFadeTimerIfIdle();

  void RequestAudioPresetChangeWithDeferredApply(int presetId, bool flag);

  void ScaleAndApplyAuxOutputVolume(short scalar); // 0x593cb0

  void SelectAndScheduleRandomAudioCue(); // 0x593790
  void UpdateAudioPlaybackStateAndScheduleRandomCue();

  void ResetDualAudioCuePools(); // 0x593730
  void AddToPlayList(int cueId); // 0x593760

  void SetActiveAudioCueAndResetQueue(int cueId, bool flag); // 0x593a10
};
ASSERT_SIZE(TSoundPlayer, 0x84);
