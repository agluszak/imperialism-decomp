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

// FUNCTION: IMPERIALISM 0x005e16f0
bool __stdcall SendMciStatusCommand814AndIgnoreFailure(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = 4;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  if (err != 0) {
    return false;
  }
  return parms.dwReturn != 0x20d;
}

// FUNCTION: IMPERIALISM 0x005e1760
unsigned int QueryMciStatusField5ViaCommand814(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = 5;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  return ~-static_cast<unsigned int>(err != 0) & parms.dwReturn;
}

// FUNCTION: IMPERIALISM 0x005e17b0
unsigned int QueryMciStatusField8ViaCommand814(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = 8;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  return ~-static_cast<unsigned int>(err != 0) & parms.dwReturn;
}

// FUNCTION: IMPERIALISM 0x005e1800
unsigned int QueryMciStatusField3ViaCommand814(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = 3;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  return ~-static_cast<unsigned int>(err != 0) & parms.dwReturn;
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
