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
  unsigned char directSoundInitOk; // set by InitializeSoundSubsystem
  bool directSoundInitPending;     // set by RequestDirectSoundInitIfAllowed
  char pad22[74];
  TLongintList* audioCuePool;
  TLongintList* remainingRandomAudioCues;
  unsigned short activeAudioCueId;
  unsigned short pendingAudioCueId;
  bool cdAudioPlaybackActive;
  unsigned char unused79; // ctor-only write; field-xrefs show no reader
  unsigned char unused7A; // ctor-only write; field-xrefs show no reader
  unsigned int fadeStartTick;
  bool clearCuePoolsAfterFade;
  char pad81[3];

  TSoundPlayer();
  // FUNCTION: IMPERIALISM 0x005933e0
  ~TSoundPlayer() override {}
  DECLARE_DYNCREATE(TSoundPlayer)
  void Free() override;
  bool DoIdle(int action) override;

  // TSoundPlayer-introduced slots (0x25+).
  virtual void ISoundPlayer(int idleFrequency);
  virtual bool DefaultSoundCapabilityPredicate();
  virtual bool DefaultSoundCompatibilityPredicate(int unusedArg1, int unusedArg2);
  virtual void RequestDirectSoundInitIfAllowed();
  virtual void CancelSoundInit();
  virtual void StopAllSounds();
  virtual void SetMasterVolumeFromPercent(short percent);
  virtual void PriorityOverride(short currentPriority, short requestedPriority);
  virtual int PlayLocalizedSound(short sfxToken, int unusedArg2 = 0, int unusedArg3 = 1,
                                 int unusedArg4 = 1);
  virtual int PlaySoundEffect(short sfxToken, int forwardedArg2 = 0, int forwardedArg3 = 1);
  virtual int PlaySndAsynchChannel(short soundId, short channel, short priority);
  virtual int PlaySndSynchChannel(short soundId, short channel, short priority);
  virtual int PlayAiffFile(CString fileName, short channel, short priority);

  bool FadeCD();

  void StopMusic(bool fadeOut);

  void StartDeferredAudioFadeTimerIfIdle();

  void RequestMusicChange(int presetId, bool flag);

  void ScaleAndApplyAuxOutputVolume(short scalar);

  void PlayRandomTrack();
  void CheckMusicStatus();

  void ResetPlayList();
  void AddToPlayList(int cueId);

  void SetActiveAudioCueAndResetQueue(int cueId, bool flag);
};
ASSERT_SIZE(TSoundPlayer, 0x84);
