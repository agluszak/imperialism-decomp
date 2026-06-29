#include "game/TSoundResourceManager.h"

TSoundResourceManager g_soundResourceManager;

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
