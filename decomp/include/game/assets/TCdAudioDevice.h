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

  void ApplyMciPlaybackRangeFromAudioManager(int trackIndex);
  void ResetAndOpenCdAudioDeviceHandle();
  void CloseDevice();
  void CloseDeviceAndClearHandle(); // 0x0047cd30
  void EnsureCdAudioDeviceHandleInitialized();
  void StopPlayback();
  int ApplyAuxOutputVolumeFromScalar(int scalar);
  BOOL IsPlaybackActive();
  int GetAuxOutputVolume();                  // 0x0047cda0
  unsigned int GetMediaPresent() const; // 0x0047ce10
  unsigned int GetCurrentTrack() const; // 0x0047ce30
  unsigned int GetTrackCount() const; // 0x0047ce50
};
// g_cdAudioDevice (0x006a60bc) is declared in game/global_data_tables.h.

int __stdcall SetAuxOutputVolumeFromScalar(int scalar);
int __stdcall SetAuxOutputVolumeByChannel(int leftVolume, int rightVolume);
int __stdcall GetAuxOutputVolumeRaw(DWORD* outVolume);
bool __stdcall SetAuxOutputVolumeAcrossCompatibleDevices(int level);
int __stdcall GetAuxOutputVolumeFromFirstCompatibleDevice(unsigned int* outVolume);

void __stdcall SetMciPlaybackRangeByTrackIndexAndDevice(int trackIndex, MCIDEVICEID device);

WORD OpenCdAudioAndProbeAuxOutputDevice(void);

bool __stdcall CloseMciDevice(MCIDEVICEID device);

void __stdcall SendMciStopCommandToDevice(MCIDEVICEID device);

int ReturnTrueStub(void);

BOOL __stdcall IsCdAudioPlaying(MCIDEVICEID device);
unsigned int GetCdMediaPresent(MCIDEVICEID device);
unsigned int GetCdCurrentTrack(MCIDEVICEID device);
unsigned int GetCdTrackCount(MCIDEVICEID device);
