#include "game/gfx/TSoundResourceManager.h"

// TSoundResourceManager.h pulls <windowsx.h> (for GlobalFreePtr in WaveLoadDescriptor),
// which defines UnionRgn/CopyRgn as GDI helper macros. Those would mangle the identically
// named QuickDraw declarations in quickdraw_regions.h, pulled in transitively below by
// global_data_tables.h. We use neither windowsx macro here, so drop them.
#undef UnionRgn
#undef CopyRgn

#include "game/ImperialismApp.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/assets/wave_helpers.h"

#include <string.h>

// DSOUND.DLL::DirectSoundCreate — imported from the DX5 SDK dsound.lib (linked in CMake).
extern "C" int __stdcall DirectSoundCreate(void* pcGuidDevice, IDirectSound** ppDS,
                                           void* pUnkOuter);

// SYNTHETIC: IMPERIALISM 0x005e4d80
// `dynamic initializer for 'g_soundResourceManager''
// SYNTHETIC: IMPERIALISM 0x005e4dc0
// TSoundResourceManager::`dynamic atexit destructor'
TSoundResourceManager g_soundResourceManager;

// Cleanup handler (registered in the shutdown handler table at 0x692668) that zeroes the
// 0x6a1e20 reset-region dword pair.
// FUNCTION: IMPERIALISM 0x0049b9d0
void ResetGlobalPair6A1E20And6A1E24() {
  g_ResetStateDword6A1E20 = 0;
  g_ResetStateDword6A1E24 = 0;
}

// FUNCTION: IMPERIALISM 0x0049b9f0
void ResetGlobalPair6A1E48And6A1E4C() {
  g_ResetStateDword6A1E48 = 0;
  g_ResetStateDword6A1E4C = 0;
}

// FUNCTION: IMPERIALISM 0x0049bc00
void ResetGlobalPair6A1E70And6A1E74() {
  g_ResetStateDword6A1E70 = 0;
  g_ResetStateDword6A1E74 = 0;
}

// FUNCTION: IMPERIALISM 0x0049bc20
void ResetGlobalPair6A1F38And6A1F3C() {
  g_ResetStateDword6A1F38 = 0;
  g_ResetStateDword6A1F3C = 0;
}

// FUNCTION: IMPERIALISM 0x0049c0c0
void InitializeGlobalPair6A1FE8And6A1FECDefault() {
  g_ScaleDefault6A1FE8 = 0.015625;
}

// FUNCTION: IMPERIALISM 0x0049c0f0
void InitializeGlobalPair6A1FC0And6A1FC4Default() {
  g_ScaleDefault6A1FC0 = 0.015625;
}

// FUNCTION: IMPERIALISM 0x0049c150
int TSoundResourceManager::CreateChannelBuffer(IDirectSoundBuffer** ppChannel) {
  WAVEFORMATEX wfx;

  wfx.wFormatTag = WAVE_FORMAT_PCM;
  wfx.nChannels = 1;
  wfx.nSamplesPerSec = 0x5622;
  wfx.nAvgBytesPerSec = 0xac44;
  wfx.nBlockAlign = 2;
  wfx.wBitsPerSample = 0x10;
  wfx.cbSize = 0;

  m_channelBufferDesc.dwSize = 0;
  m_channelBufferDesc.dwFlags = 0;
  m_channelBufferDesc.dwBufferBytes = 0;
  m_channelBufferDesc.dwReserved = 0;
  m_channelBufferDesc.lpwfxFormat = 0;
  m_channelBufferDesc.dwFlags = 0xe0;
  m_channelBufferDesc.dwBufferBytes = 0x35e1c;
  m_channelBufferDesc.lpwfxFormat = &wfx;
  m_channelBufferDesc.dwSize = 0x14;
  if (m_device->CreateSoundBuffer(&m_channelBufferDesc, ppChannel, 0) == 0) {
    DSBCAPS caps;
    caps.dwSize = 0x14;
    if ((*ppChannel)->GetCaps(&caps) == 0) {
      return 1;
    }
  }
  *ppChannel = 0;
  return 0;
}

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
  WaveLoadFile(filePath, &desc.cbWaveSize, &desc.cSamples, &desc.pwfx, &desc.pbWaveData, 0);
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
    failed =
        WaveLoadFile(filePath, &desc.cbWaveSize, &desc.cSamples, &desc.pwfx, &desc.pbWaveData, 0);
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
    failed =
        WaveLoadFile(0, &desc.cbWaveSize, &desc.cSamples, &desc.pwfx, &desc.pbWaveData, &mmioInfo);
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

  int result = m_channels[slot]->Lock(0, m_channelBufferDesc.dwBufferBytes, &audioPtr1,
                                      &audioBytes1, &audioPtr2, &audioBytes2, 0);
  if (result == (int)DSERR_BUFFERLOST) {
    m_channels[slot]->Restore();
    result = m_channels[slot]->Lock(0, m_channelBufferDesc.dwBufferBytes, &audioPtr1, &audioBytes1,
                                    &audioPtr2, &audioBytes2, 0);
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

// Release the six channel buffers, the DirectSound device, and the wave-pack module.
// The original runs this (via TSoundPlayer slot 0x29) right before starting MCIWnd
// movie playback so the AVI audio can open the wave device.
// FUNCTION: IMPERIALISM 0x0049c8e0
void TSoundResourceManager::ReleaseDirectSoundDeviceAndChannels() {
  for (int i = 0; i < 6; ++i) {
    if (m_channels[i] != 0) {
      m_channels[i]->Release();
      m_channels[i] = 0;
    }
  }
  if (m_device != 0) {
    m_device->Release();
    m_device = 0;
  }
  if (m_module != 0) {
    FreeLibrary(m_module);
    m_module = 0;
  }
}

// FUNCTION: IMPERIALISM 0x0049c970
int TSoundResourceManager::InitializeDirectSoundDeviceAndChannels() {
  if (m_device != 0) {
    return 1;
  }
  if (m_module == 0) {
    m_module = LoadLibraryExA(g_pImperialismApp->field_DC, 0, LOAD_LIBRARY_AS_DATAFILE);
  }
  m_field34 = DirectSoundCreate(0, &m_device, 0);
  if (m_field34 != 0) {
    m_device = 0;
    return 0;
  }
  CWnd* pMainWnd;
  if (AfxGetThread() != 0) {
    pMainWnd = AfxGetThread()->GetMainWnd();
  } else {
    pMainWnd = 0;
  }
  void* hwnd;
  if (pMainWnd != 0) {
    hwnd = pMainWnd->m_hWnd;
  } else {
    hwnd = 0;
  }
  m_field34 = m_device->SetCooperativeLevel(hwnd, DSSCL_NORMAL);
  IDirectSoundBuffer** ppChannel = m_channels;
  int i = 6;
  do {
    CreateChannelBuffer(ppChannel);
    ++ppChannel;
    --i;
  } while (i != 0);
  return 1;
}
