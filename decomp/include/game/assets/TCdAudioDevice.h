#pragma once

#include "game/mfc.h"

#include <mmsystem.h>

struct TCdAudioDevice {
  MCIDEVICEID m_deviceId;

  TCdAudioDevice() {
    ResetAndOpenCdAudioDeviceHandle();
  }
  ~TCdAudioDevice() {
    CloseDeviceAndClearHandle();
  }

  void ApplyMciPlaybackRangeFromAudioManager(int trackIndex);
  void ResetAndOpenCdAudioDeviceHandle();
  void CloseDevice();
  void CloseDeviceAndClearHandle();
  void EnsureCdAudioDeviceHandleInitialized();
  void StopPlayback();
  int ApplyAuxOutputVolumeFromScalar(int scalar);
  BOOL IsPlaybackActive();
  int GetAuxOutputVolume();
  unsigned int GetMediaPresent() const;
  unsigned int GetCurrentTrack() const;
  unsigned int GetTrackCount() const;
};

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
