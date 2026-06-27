#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

// Global sound/wave resource manager living at 0x006a60c0. It owns an array of six
// polymorphic audio-channel objects (+0x04..+0x18), the wave-pack module handle (+0x30) and a
// scratch result slot (+0x34). The three methods below are real __thiscall members reached
// from TSoundPlayer (previously through dummy-edx __fastcall casts).
//
// The channel objects are a not-yet-recovered polymorphic class; we only need three of its
// vtable slots (0x30/0x34/0x3c), so it is modelled here as an abstract interface with real
// virtuals at the verified slot offsets (Hard Rule 12 — dispatch to an unrecovered receiver
// via a real virtual at the verified slot, never raw vftable indexing). Names are provisional.
class TAudioChannel {
public:
#define AUDIO_CHANNEL_DUMMY(n) virtual void AudioChannelDummy##n() = 0
  AUDIO_CHANNEL_DUMMY(00);                                  // 0x00
  AUDIO_CHANNEL_DUMMY(04);                                  // 0x04
  AUDIO_CHANNEL_DUMMY(08);                                  // 0x08
  AUDIO_CHANNEL_DUMMY(0c);                                  // 0x0c
  AUDIO_CHANNEL_DUMMY(10);                                  // 0x10
  AUDIO_CHANNEL_DUMMY(14);                                  // 0x14
  AUDIO_CHANNEL_DUMMY(18);                                  // 0x18
  AUDIO_CHANNEL_DUMMY(1c);                                  // 0x1c
  AUDIO_CHANNEL_DUMMY(20);                                  // 0x20
  AUDIO_CHANNEL_DUMMY(24);                                  // 0x24
  AUDIO_CHANNEL_DUMMY(28);                                  // 0x28
  AUDIO_CHANNEL_DUMMY(2c);                                  // 0x2c
  virtual int StartPlaybackSlot30(int a, int b, int c) = 0; // 0x30
  virtual int RefreshVoiceStateSlot34(int a) = 0;           // 0x34
  AUDIO_CHANNEL_DUMMY(38);                                  // 0x38
  virtual int SetChannelVolumeSlot3C(int volume) = 0;       // 0x3c
#undef AUDIO_CHANNEL_DUMMY
};

class TSoundResourceManager {
public:
  // 0x0049c240 — rotate to channel `slot`, refresh its voice state and (re)start playback.
  int UpdateLocalizationAudioSlot(int slot);
  // 0x0049c430 — load wave resource `waveId` from a file or the wave module and build a buffer.
  int LoadWaveResourceByNumericIdAndBuildBuffer(unsigned int waveId, int param2);
  // 0x0049c850 — push `volume` to every channel until one accepts it.
  int SetChannelVolumesUntilAccepted(int volume);

  void* m_field0;               // 0x00
  TAudioChannel* m_channels[6]; // 0x04..0x18
  char m_pad1c[0x14];           // 0x1c..0x2f
  HMODULE m_module;             // 0x30 (wave-pack module datafile)
  int m_field34;                // 0x34 (last channel result / built buffer handle)
};

extern "C" TSoundResourceManager g_soundResourceManager;
