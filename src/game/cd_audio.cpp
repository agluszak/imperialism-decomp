#include "game/cd_audio.h"

#include "game/global_data_tables.h"

TCdAudioDevice g_cdAudioDevice; // 0x006a60bc

// FUNCTION: IMPERIALISM 0x0047cd60
void TCdAudioDevice::ApplyMciPlaybackRangeFromAudioManager(int trackIndex) {
  SetMciPlaybackRangeByTrackIndexAndDevice(trackIndex, m_deviceId);
}

// FUNCTION: IMPERIALISM 0x005df8d0
int ReturnTrueStub(void) {
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e1850
void __stdcall SetMciPlaybackRangeByTrackIndexAndDevice(int trackIndex, MCIDEVICEID device) {
  MCI_SET_PARMS setParms;
  MCI_PLAY_PARMS playParms;

  setParms.dwTimeFormat = MCI_FORMAT_TMSF;
  if (mciSendCommandA(device, MCI_SET, MCI_SET_TIME_FORMAT, (DWORD)&setParms) == 0) {
    playParms.dwFrom = static_cast<DWORD>(trackIndex & 0xff);
    playParms.dwTo = static_cast<DWORD>((trackIndex + 1) & 0xff);
    if (mciSendCommandA(device, MCI_PLAY, MCI_FROM, (DWORD)&playParms) == 0) {
      mciSendCommandA(device, MCI_PLAY, MCI_TO, (DWORD)&playParms);
    }
  }
}
