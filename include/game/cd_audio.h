#pragma once

#include "game/mfc.h"

#include <mmsystem.h>

// The CD-audio device "singleton" is a bare 4-byte global at 0x006a60bc holding the open MCI
// device id (opened elsewhere in the multimedia subsystem). The thiscall helper below takes
// &g_cdAudioDevice in ECX and reads that id.
struct TCdAudioDevice {
  MCIDEVICEID m_deviceId; // 0x00

  // 0x0047cd60 — set the MCI time format to TMSF and play the given CD track's range.
  void ApplyMciPlaybackRangeFromAudioManager(int trackIndex);
  // 0x0047cca0 — clear then (re)open the device handle.
  void ResetAndOpenCdAudioDeviceHandle();
  // 0x0047ccd0 — if a device is open, send MCI command 0x804 to it and clear the handle.
  void SendMciCommand804IfDeviceOpenAndClearHandle();
  // 0x0047cd00 — open the device handle only if it is not already set.
  void EnsureCdAudioDeviceHandleInitialized();
  // 0x0047cdf0 — forward the current handle to the MCI_STATUS (0x814) helper; returns its result.
  bool ForwardMciStatusCommand814IgnoreFailure();
};
// g_cdAudioDevice (0x006a60bc) is declared in game/global_data_tables.h.

// Thin forwarder (0x0047cdd0) -- doubles scalar into both aux-volume channel words and
// applies it via SetAuxOutputVolumeFromScalar.
int __stdcall ApplyAuxOutputVolumeFromScalar(int scalar);

// Aux-output (CD-audio line) volume: g_nAuxOutputDeviceIndex (global_data_tables.h) holds
// the probed aux device index (-1 = none found; set by the still-unported
// ProbeAuxOutputDeviceIndexByPidMask, 0x005e1430, which sits in this same address cluster
// between WaveLoadFile's end and these functions -- part of this module, not wave.c).
// 0x005e1500 -- duplicates dwVolume into both channel words and calls winmm auxSetVolume.
int __stdcall SetAuxOutputVolumeFromScalar(int scalar);
// 0x005e1590 -- sets volume on every aux device whose wPid&7 is 1 or 2; returns whether the
// last auxGetDevCaps call succeeded.
bool __stdcall SetAuxOutputVolumeAcrossCompatibleDevices(int level);
// 0x005e1620 -- reads volume (>>9 & 0x7f) from the first aux device whose wPid&7==1.
int __stdcall GetAuxOutputVolumeFromFirstCompatibleDevice(unsigned int* outVolume);

// 0x005e1850 — issue the MCI_SET (TMSF) + MCI_PLAY (from/to) command sequence for a track.
void __stdcall SetMciPlaybackRangeByTrackIndexAndDevice(int trackIndex, MCIDEVICEID device);

// 0x005e18f0 — open the CD-audio MCI device and probe the aux-output device; returns the id.
unsigned int OpenCdAudioAndProbeAuxOutputDevice(void);

// 0x005e19e0 — send MCI command 0x804 to the given device; returns true on success.
bool __stdcall SendMciCommand804ToDevice(MCIDEVICEID device);

// 0x005df8d0 — shared predicate stub, always returns 1 (the audio-changed feature is a no-op
// in the retail build). Called with an unused receiver in ECX at every call site.
int ReturnTrueStub(void);

// 0x5e16f0 / 0x5e1760 / 0x5e17b0 / 0x5e1800 — MCI_STATUS (0x814) queries on a CD-audio device
// for dwItem 4/5/8/3; the Query* variants mask dwReturn to 0 on MCI failure.
bool __stdcall SendMciStatusCommand814AndIgnoreFailure(MCIDEVICEID device);
unsigned int QueryMciStatusField5ViaCommand814(MCIDEVICEID device);
unsigned int QueryMciStatusField8ViaCommand814(MCIDEVICEID device);
unsigned int QueryMciStatusField3ViaCommand814(MCIDEVICEID device);
