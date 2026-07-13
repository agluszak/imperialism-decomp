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
};
// g_cdAudioDevice (0x006a60bc) is declared in game/global_data_tables.h.

// 0x005e1850 — issue the MCI_SET (TMSF) + MCI_PLAY (from/to) command sequence for a track.
void __stdcall SetMciPlaybackRangeByTrackIndexAndDevice(int trackIndex, MCIDEVICEID device);

// 0x005df8d0 — shared predicate stub, always returns 1 (the audio-changed feature is a no-op
// in the retail build). Called with an unused receiver in ECX at every call site.
int ReturnTrueStub(void);

// 0x5e16f0 / 0x5e1760 / 0x5e17b0 / 0x5e1800 — MCI_STATUS (0x814) queries on a CD-audio device
// for dwItem 4/5/8/3; the Query* variants mask dwReturn to 0 on MCI failure.
bool __stdcall SendMciStatusCommand814AndIgnoreFailure(MCIDEVICEID device);
unsigned int QueryMciStatusField5ViaCommand814(MCIDEVICEID device);
unsigned int QueryMciStatusField8ViaCommand814(MCIDEVICEID device);
unsigned int QueryMciStatusField3ViaCommand814(MCIDEVICEID device);
