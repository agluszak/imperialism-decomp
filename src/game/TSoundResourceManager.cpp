#include "game/TSoundResourceManager.h"

// GLOBAL: IMPERIALISM 0x6a60c0
extern "C" TSoundResourceManager g_soundResourceManager;
TSoundResourceManager g_soundResourceManager;

undefined4 LoadWaveResourceByNumericIdAndBuildBuffer(void);

int TSoundResourceManager::LoadWaveResourceByNumericIdAndBuildBuffer(unsigned int waveId, int param2) {
  typedef int (__fastcall *LoadWaveFunc)(void*, int, int, int);
  return reinterpret_cast<LoadWaveFunc>(::LoadWaveResourceByNumericIdAndBuildBuffer)(
      this, 0, waveId, param2);
}

// FUNCTION: IMPERIALISM 0x0049c240
int TSoundResourceManager::UpdateLocalizationAudioSlot(int slot) {
  TAudioChannel* channel = m_channels[slot];
  int result = channel->RefreshVoiceStateSlot34(0);
  if (result == 0) {
    channel = m_channels[slot];
    result = channel->StartPlaybackSlot30(0, 0, 0);
  }
  return result == 0;
}

// FUNCTION: IMPERIALISM 0x0049c850
int TSoundResourceManager::SetChannelVolumesUntilAccepted(int volume) {
  for (int i = 0; i < 6; ++i) {
    int result = m_channels[i]->SetChannelVolumeSlot3C(volume);
    m_field34 = result;
    if (result != 0) {
      return 0;
    }
  }
  return 1;
}
