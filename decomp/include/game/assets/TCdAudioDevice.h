#pragma once

#include "game/mfc.h"

#include <mmsystem.h>

struct TCdAudioDevice {
  MCIDEVICEID m_deviceId; // 0x00

  TCdAudioDevice() {
    ResetAndOpenCdAudioDeviceHandle();
  }
  ~TCdAudioDevice() {
    CloseDeviceAndClearHandle();
  }

  // 0x0047cd60 — set the MCI time format to TMSF and play the given CD track's range.
  void ApplyMciPlaybackRangeFromAudioManager(int trackIndex);
  // 0x0047cca0 — clear then (re)open the device handle.
  void ResetAndOpenCdAudioDeviceHandle();
  // 0x0047ccd0 — if a device is open, send MCI command 0x804 to it and clear the handle.
  void CloseDevice();
  void CloseDeviceAndClearHandle(); // 0x0047cd30
  // 0x0047cd00 — open the device handle only if it is not already set.
  void EnsureCdAudioDeviceHandleInitialized();
  // 0x0047cd80 — stop playback on the current MCI device.
  void StopPlayback();
  // 0x0047cdd0 — scale one 16-bit value into both aux-output channels.
  int ApplyAuxOutputVolumeFromScalar(int scalar);
  // 0x0047cdf0 — true while the current MCI device is not stopped (and its status query succeeds).
  BOOL IsPlaybackActive();
  int GetAuxOutputVolume();                  // 0x0047cda0
  unsigned int GetMediaPresent() const; // 0x0047ce10
  unsigned int GetCurrentTrack() const; // 0x0047ce30
  unsigned int GetTrackCount() const; // 0x0047ce50
};
// g_cdAudioDevice (0x006a60bc) is declared in game/global_data_tables.h.

int __stdcall SetAuxOutputVolumeFromScalar(int scalar);
// 0x005e14c0 -- combines independently supplied left and right channel words.
int __stdcall SetAuxOutputVolumeByChannel(int leftVolume, int rightVolume);
// 0x005e1540 -- returns the raw packed left/right channel volume.
int __stdcall GetAuxOutputVolumeRaw(DWORD* outVolume);
bool __stdcall SetAuxOutputVolumeAcrossCompatibleDevices(int level);
// 0x005e1620 -- reads volume (>>9 & 0x7f) from the first aux device whose wPid&7==1.
int __stdcall GetAuxOutputVolumeFromFirstCompatibleDevice(unsigned int* outVolume);

// 0x005e1850 — issue the MCI_SET (TMSF) + MCI_PLAY (from/to) command sequence for a track.
void __stdcall SetMciPlaybackRangeByTrackIndexAndDevice(int trackIndex, MCIDEVICEID device);

// 0x005e18f0 — open the CD-audio MCI device and probe the aux-output device; returns the id.
WORD OpenCdAudioAndProbeAuxOutputDevice(void);

// 0x005e19e0 — send MCI command 0x804 to the given device; returns true on success.
bool __stdcall CloseMciDevice(MCIDEVICEID device);

void __stdcall SendMciStopCommandToDevice(MCIDEVICEID device);

int ReturnTrueStub(void);

BOOL __stdcall IsCdAudioPlaying(MCIDEVICEID device);
unsigned int GetCdMediaPresent(MCIDEVICEID device);
unsigned int GetCdCurrentTrack(MCIDEVICEID device);
unsigned int GetCdTrackCount(MCIDEVICEID device);
