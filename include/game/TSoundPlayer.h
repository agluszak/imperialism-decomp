#pragma once

#include "game/TEventHandler.h"
#include "game/global_data_tables.h"
#include "game/TLongintList.h"

struct CRuntimeClass;

// Sound subsystem controller (TEventHandler descendant). Size 0x84.
// VTABLE: IMPERIALISM 0x668a60
class TSoundPlayer : public TEventHandler {
public:
  unsigned char directSoundInitOkAt20;      // 0x20 — set by InitializeSoundSubsystem
  unsigned char directSoundInitPendingAt21; // 0x21 — set by RequestDirectSoundInitIfAllowed
  char pad22[0x4a];
  TLongintList* runtimePeerAt6c;
  TLongintList* runtimePeerAt70;
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
  ~TSoundPlayer() override; // 0x5933e0 (slot 0x01 scalar deleting dtor 0x5933b0)
  DECLARE_DYNCREATE(TSoundPlayer)
  void EnsureCdAudioDeviceHandleInitialized();
  void ForwardMciCommand808ToDevice();
  BOOL ForwardMciStatusCommand814IgnoreFailure();

  void Free() override;             // 0x07 -> 0x5e51d0
  char DoIdle(int action) override; // 0x13 -> 0x593400

  // TSoundPlayer-introduced slots (0x25+).
  virtual void InitializeSoundSubsystemAndAllocateChannelLists(int param_1); // 0x25 -> 0x5e4e70
  virtual unsigned char ReturnConstantTrue_SoundPredicate();                 // 0x26 -> 0x5e4f60
  virtual unsigned char ReturnConstantFalse_SoundPredicate(int a, int b);    // 0x27 -> 0x5e4fb0
  virtual void RequestDirectSoundInitIfAllowed();                            // 0x28 -> 0x5e4f80
  virtual void ClearDirectSoundInitPendingAndResetState();                   // 0x29 -> 0x5e4fd0
  virtual void StopAllSoundChannels();                                       // 0x2a -> 0x5e4ff0
  // Converts a 0-100 percent into log-taper DirectSound attenuation (clamped to
  // [-9999, 0] millibels) and applies it when DirectSound init succeeded.
  virtual void SetMasterVolumeFromPercent(short percent); // 0x2b -> 0x5e5020
  virtual void NoOpAudioTickCallback_005e50a0();          // 0x2c -> 0x5e50a0
  // sfxToken is short-typed: the body reads it via `movsx ecx, word ptr [esp+8]`
  // (0x5e50f0) and PlaySoundEffect forwards its own short token without extension.
  virtual int UpdateLocalizationAudioSlotAndMaybeRefreshVoiceState(
      short sfxToken, int param_2 = 0, int param_3 = 1, int param_4 = 1); // 0x2d -> 0x5e50c0
  // sfxToken is short-typed: 0x5d6260 passes a word table load with no extension
  // (garbage upper bits), which only compiles against a short parameter.
  virtual int PlaySoundEffect(short sfxToken, int param_2 = 0, int param_3 = 1); // 0x2e -> 0x5e5140

  void HandleBlinkStateAndScheduleTimerTick(char enabled); // 0x593c10

  // Non-virtual: queue an audio-preset (music cue) change applied on the next audio
  // tick. Called with rand%3+6 for the tactical-battle cues. Both original callsites
  // load ECX = g_pSfxPlaybackSystem. 0x593920.
  void RequestAudioPresetChangeWithDeferredApply(int presetId, bool flag);

  // Non-virtual: scale a 0-255 aux-volume preference into the 16-bit auxSetVolume range
  // (scalar << 8) and apply it to the probed aux output device (CD-audio line). Both
  // original callsites (0x5db66f, 0x56e734) load ECX = g_pSfxPlaybackSystem.
  void ScaleAndApplyAuxOutputVolume(short scalar); // 0x593cb0

  // Non-virtual: pick a random CD-audio cue from the peer queues and (re)schedule it, driving
  // the MCI playback range and the deferred-apply timer. Every callsite loads
  // ECX = g_pSfxPlaybackSystem.
  void SelectAndScheduleRandomAudioCue(); // 0x593790

  // Non-virtual: reset both channel peers' active playback (StopOrResetActivePlaybackSlot30
  // on each). Callsite 0x5db798 (TViewMgr::UiRuntimeSlotF8) loads ECX = g_pSfxPlaybackSystem.
  void ResetDualAudioCuePools(); // 0x593730
  // Non-virtual: push cueId onto both channel peers' queues (InsertLast on
  // each). Same callsite as above.
  void PushCueToDualAudioCuePools(int cueId); // 0x593760

  // Non-virtual: force-switch to cueId, clearing any pending random-cue rotation state or
  // deferred preset-change state in the process, then reset both channel peers' queues to
  // hold just cueId and (re)apply it as the active preset (deferred if flag is set and a
  // preset is already active). All 3 original callsites (in
  // TSimMgr::AdvanceGlobalTurnStateMachine) load ECX = g_pSfxPlaybackSystem and pass
  // cueId=4, flag=true.
  void SetActiveAudioCueAndResetQueue(int cueId, bool flag); // 0x593a10
};
