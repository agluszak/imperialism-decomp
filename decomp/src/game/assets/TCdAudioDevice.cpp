#include "game/assets/TCdAudioDevice.h"
#include "game/pointer_representation.h"

#include "game/globals/global_types.h"
#include "game/globals/assets_globals.h"
#include "game/globals/shared_globals.h"

TCdAudioDevice g_cdAudioDevice;

// FUNCTION: IMPERIALISM 0x0047cca0
void TCdAudioDevice::ResetAndOpenCdAudioDeviceHandle() {
  m_deviceId = 0;
  m_deviceId = OpenCdAudioAndProbeAuxOutputDevice();
}

// FUNCTION: IMPERIALISM 0x0047ccd0
void TCdAudioDevice::CloseDevice() {
  if (m_deviceId != 0) {
    CloseMciDevice(m_deviceId);
    m_deviceId = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0047cd00
void TCdAudioDevice::EnsureCdAudioDeviceHandleInitialized() {
  if (m_deviceId == 0) {
    m_deviceId = OpenCdAudioAndProbeAuxOutputDevice();
  }
}

// FUNCTION: IMPERIALISM 0x0047cd30
void TCdAudioDevice::CloseDeviceAndClearHandle() {
  if (m_deviceId != 0) {
    CloseMciDevice(m_deviceId);
    m_deviceId = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0047cd60
void TCdAudioDevice::ApplyMciPlaybackRangeFromAudioManager(int trackIndex) {
  SetMciPlaybackRangeByTrackIndexAndDevice(trackIndex, m_deviceId);
}

// FUNCTION: IMPERIALISM 0x0047cd80
void TCdAudioDevice::StopPlayback() {
  SendMciStopCommandToDevice(m_deviceId);
}

// FUNCTION: IMPERIALISM 0x0047cda0
int TCdAudioDevice::GetAuxOutputVolume() {
  unsigned int volume;
  GetAuxOutputVolumeFromFirstCompatibleDevice(&volume);
  return volume;
}

// FUNCTION: IMPERIALISM 0x0047cdd0
int TCdAudioDevice::ApplyAuxOutputVolumeFromScalar(int scalar) {
  return SetAuxOutputVolumeFromScalar(scalar);
}

// FUNCTION: IMPERIALISM 0x0047cdf0
BOOL TCdAudioDevice::IsPlaybackActive() {
  return IsCdAudioPlaying(m_deviceId);
}

// FUNCTION: IMPERIALISM 0x0047ce10
unsigned int TCdAudioDevice::GetMediaPresent() const {
  return GetCdMediaPresent(m_deviceId);
}

// FUNCTION: IMPERIALISM 0x0047ce30
unsigned int TCdAudioDevice::GetCurrentTrack() const {
  return GetCdCurrentTrack(m_deviceId);
}

// FUNCTION: IMPERIALISM 0x0047ce50
unsigned int TCdAudioDevice::GetTrackCount() const {
  return GetCdTrackCount(m_deviceId);
}

// FUNCTION: IMPERIALISM 0x005df8d0
int ReturnTrueStub(void) {
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e14c0
int __stdcall SetAuxOutputVolumeByChannel(int leftVolume, int rightVolume) {
  if (g_nAuxOutputDeviceIndex == -1) {
    return 0;
  }
  auxSetVolume(g_nAuxOutputDeviceIndex, (rightVolume << 16) + leftVolume);
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e1500
int __stdcall SetAuxOutputVolumeFromScalar(int scalar) {
  if (g_nAuxOutputDeviceIndex == -1) {
    return 0;
  }
  auxSetVolume(g_nAuxOutputDeviceIndex, (scalar << 16) + scalar);
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e1540
int __stdcall GetAuxOutputVolumeRaw(DWORD* outVolume) {
  DWORD volume = 0;
  if (g_nAuxOutputDeviceIndex == -1) {
    return 0;
  }
  auxGetVolume(g_nAuxOutputDeviceIndex, &volume);
  *outVolume = volume;
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e1590
bool __stdcall SetAuxOutputVolumeAcrossCompatibleDevices(int level) {
  MMRESULT result = 0;
  UINT numDevs = auxGetNumDevs();
  UINT deviceId = 0;
  if (static_cast<int>(numDevs) > 0) {
    tagAUXCAPSA caps;
    do {
      result = auxGetDevCapsA(deviceId, &caps, sizeof(tagAUXCAPSA));
      unsigned short pidLow = caps.wPid & 7;
      if (pidLow == 1 || pidLow == 2) {
        auxSetVolume(deviceId, level * 0x2000200);
      }
      ++deviceId;
    } while (static_cast<int>(deviceId) < static_cast<int>(numDevs));
  }
  return result == 0;
}

// FUNCTION: IMPERIALISM 0x005e1620
int __stdcall GetAuxOutputVolumeFromFirstCompatibleDevice(unsigned int* outVolume) {
  tagAUXCAPSA caps;
  DWORD volume;
  UINT deviceId = 0;
  UINT numDevs = auxGetNumDevs();
  if (static_cast<int>(numDevs) < 1) {
    return 0;
  }
  do {
    MMRESULT result = auxGetDevCapsA(deviceId, &caps, 0x30);
    auxGetVolume(deviceId, &volume);
    if ((static_cast<unsigned char>(caps.wPid) & 7) == 1) {
      if (result == 0) {
        *outVolume = (volume >> 9) & 0x7f;
        return 1;
      }
      *outVolume = 0;
    }
    ++deviceId;
  } while (static_cast<int>(deviceId) < static_cast<int>(numDevs));
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e16f0
BOOL __stdcall IsCdAudioPlaying(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = MCI_STATUS_MODE;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  if (err != 0) {
    return FALSE;
  }
  return parms.dwReturn != MCI_MODE_STOP;
}

// FUNCTION: IMPERIALISM 0x005e1760
unsigned int GetCdMediaPresent(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = MCI_STATUS_MEDIA_PRESENT;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  return err == 0 ? parms.dwReturn : 0;
}

// FUNCTION: IMPERIALISM 0x005e17b0
unsigned int GetCdCurrentTrack(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = MCI_STATUS_CURRENT_TRACK;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  return err == 0 ? parms.dwReturn : 0;
}

// FUNCTION: IMPERIALISM 0x005e1800
unsigned int GetCdTrackCount(MCIDEVICEID device) {
  MCI_STATUS_PARMS parms;
  parms.dwItem = MCI_STATUS_NUMBER_OF_TRACKS;
  MCIERROR err = mciSendCommandA(device, MCI_STATUS, MCI_STATUS_ITEM, (DWORD)&parms);
  return err == 0 ? parms.dwReturn : 0;
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

// FUNCTION: IMPERIALISM 0x005e18f0
WORD OpenCdAudioAndProbeAuxOutputDevice(void) {
  MCI_OPEN_PARMS openParams;
  openParams.dwCallback = 0;
  openParams.wDeviceID = 0;
  openParams.lpstrDeviceType = "cdaudio";
  openParams.lpstrElementName = 0;
  openParams.lpstrAlias = 0;

  MCIERROR openResult =
      mciSendCommandA(0, MCI_OPEN, MCI_OPEN_TYPE | MCI_OPEN_SHAREABLE, (DWORD)&openParams);
  if (openResult != 0) {
    return 0;
  }

  MMRESULT auxResult = 0;
  int deviceCount = auxGetNumDevs();
  int deviceId = 0;
  if (deviceCount > 0) {
    AUXCAPSA caps;
    while (deviceId < deviceCount) {
      auxResult = auxGetDevCapsA(deviceId, &caps, sizeof(caps));
      WORD deviceKind = caps.wPid & 7;
      if (deviceKind == 1 || deviceKind == 2) {
        g_nAuxOutputDeviceIndex = deviceId;
        break;
      }
      ++deviceId;
    }
  }

  if (auxResult != MMSYSERR_NOERROR) {
    g_nAuxOutputDeviceIndex = -1;
    return 0;
  }
  return openParams.wDeviceID;
}

// FUNCTION: IMPERIALISM 0x005e19e0
bool __stdcall CloseMciDevice(MCIDEVICEID device) {
  MCIERROR err = mciSendCommandA(device, 0x804, 0, 0);
  return err == 0;
}

// FUNCTION: IMPERIALISM 0x005e1a10
void __stdcall SendMciStopCommandToDevice(MCIDEVICEID device) {
  mciSendCommandA(device, MCI_STOP, 0, reinterpret_cast<DWORD>(&device));
}
