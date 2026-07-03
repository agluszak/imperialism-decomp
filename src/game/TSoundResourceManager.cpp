#include "game/TSoundResourceManager.h"

#include "game/wave_helpers.h"

#include <string.h>

TSoundResourceManager g_soundResourceManager;

// FUNCTION: IMPERIALISM 0x0049c240
int TSoundResourceManager::UpdateLocalizationAudioSlot(int slot) {
  IDirectSoundBuffer* channel = m_channels[slot];
  int result = channel->SetCurrentPosition(0);
  if (result == 0) {
    channel = m_channels[slot];
    result = channel->Play(0, 0, 0);
  }
  return result == 0;
}

// FUNCTION: IMPERIALISM 0x0049c290
int TSoundResourceManager::LoadWaveFileByPathAndBuildBuffer(char* filePath, int slot) {
  WaveLoadDescriptor desc;
  LoadWaveDataAndFormatFromFilePath(filePath, &desc.cbWaveSize, &desc.cSamples, &desc.pwfx,
                                    &desc.pbWaveData, 0);
  return ReadWaveDataAndFormatViaLoaderWithRetry(&desc, slot);
}

// FUNCTION: IMPERIALISM 0x0049c430
int TSoundResourceManager::LoadWaveResourceByNumericIdAndBuildBuffer(unsigned int waveId,
                                                                     int slot) {
  WaveLoadDescriptor desc;
  int failed;
  {
    CString fileName;
    fileName.Format("%d.wav", waveId);
    char* filePath = fileName.GetBuffer(0);
    if (desc.pwfx != 0) {
      GlobalFreePtr(desc.pwfx);
    }
    desc.pwfx = 0;
    if (desc.pbWaveData != 0) {
      GlobalFreePtr(desc.pbWaveData);
    }
    desc.pbWaveData = 0;
    failed = LoadWaveDataAndFormatFromFilePath(filePath, &desc.cbWaveSize, &desc.cSamples,
                                               &desc.pwfx, &desc.pbWaveData, 0);
    fileName.ReleaseBuffer(-1);
  }
  if (failed != 0) {
    HMODULE module = m_module;
    MMIOINFO mmioInfo;
    if (desc.pwfx != 0) {
      GlobalFreePtr(desc.pwfx);
    }
    desc.pwfx = 0;
    if (desc.pbWaveData != 0) {
      GlobalFreePtr(desc.pbWaveData);
    }
    desc.pbWaveData = 0;
    memset(&mmioInfo, 0, sizeof(mmioInfo));
    mmioInfo.dwFlags = 0;
    HRSRC resInfo = FindResourceA(module, (LPCSTR)(waveId & 0xffff), "WAVE");
    if (resInfo == 0) {
      return 0;
    }
    mmioInfo.pchBuffer = (HPSTR)LoadResource(module, resInfo);
    mmioInfo.fccIOProc = mmioFOURCC('M', 'E', 'M', ' ');
    mmioInfo.cchBuffer = SizeofResource(module, resInfo);
    failed = LoadWaveDataAndFormatFromFilePath(0, &desc.cbWaveSize, &desc.cSamples, &desc.pwfx,
                                               &desc.pbWaveData, &mmioInfo);
    if (failed != 0) {
      return 0;
    }
  }
  return ReadWaveDataAndFormatViaLoaderWithRetry(&desc, slot);
}

// FUNCTION: IMPERIALISM 0x0049c720
int TSoundResourceManager::ReadWaveDataAndFormatViaLoaderWithRetry(WaveLoadDescriptor* desc,
                                                                   int slot) {
  void* audioPtr1;
  DWORD audioBytes1;
  void* audioPtr2;
  DWORD audioBytes2;

  int result = m_channels[slot]->Lock(0, m_channelBufferBytes, &audioPtr1, &audioBytes1, &audioPtr2,
                                      &audioBytes2, 0);
  if (result == (int)DSERR_BUFFERLOST) {
    m_channels[slot]->Restore();
    result = m_channels[slot]->Lock(0, m_channelBufferBytes, &audioPtr1, &audioBytes1, &audioPtr2,
                                    &audioBytes2, 0);
  }
  if (result == 0) {
    memcpy(audioPtr1, desc->pbWaveData, desc->cbWaveSize);
    unsigned int fillIndex = (int)desc->cbWaveSize / 2;
    while (fillIndex < audioBytes1 / 2) {
      ++fillIndex;
      ((short*)audioPtr1)[fillIndex - 1] = 0;
    }
    result = m_channels[slot]->Unlock(audioPtr1, audioBytes1, audioPtr2, audioBytes2);
  }
  return result == 0;
}

// FUNCTION: IMPERIALISM 0x0049c850
int TSoundResourceManager::SetChannelVolumesUntilAccepted(int volume) {
  for (int i = 0; i < 6; ++i) {
    int result = m_channels[i]->SetVolume(volume);
    m_field34 = result;
    if (result != 0) {
      return 0;
    }
  }
  return 1;
}
