#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

#include <mmsystem.h>
#include <windowsx.h>

// Global sound resource manager: six DirectSound channels and the wave-pack module.

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
class IDirectSoundBuffer {
public:
  virtual int __stdcall QueryInterface(void* riid, void** ppvObj) = 0; // 0x00
  virtual unsigned long __stdcall AddRef() = 0;                        // 0x04
  virtual unsigned long __stdcall Release() = 0;                       // 0x08
  virtual int __stdcall GetCaps(void* pDSBufferCaps) = 0;              // 0x0c
  virtual int __stdcall GetCurrentPosition(DWORD* pdwCurrentPlayCursor,
                                           DWORD* pdwCurrentWriteCursor) = 0; // 0x10
  virtual int __stdcall GetFormat(void* pwfxFormat, DWORD dwSizeAllocated,
                                  DWORD* pdwSizeWritten) = 0;                     // 0x14
  virtual int __stdcall GetVolume(long* plVolume) = 0;                            // 0x18
  virtual int __stdcall GetPan(long* plPan) = 0;                                  // 0x1c
  virtual int __stdcall GetFrequency(DWORD* pdwFrequency) = 0;                    // 0x20
  virtual int __stdcall GetStatus(DWORD* pdwStatus) = 0;                          // 0x24
  virtual int __stdcall Initialize(void* pDirectSound, void* pcDSBufferDesc) = 0; // 0x28
  virtual int __stdcall Lock(DWORD dwOffset, DWORD dwBytes, void** ppvAudioPtr1,
                             DWORD* pdwAudioBytes1, void** ppvAudioPtr2, DWORD* pdwAudioBytes2,
                             DWORD dwFlags) = 0;                                      // 0x2c
  virtual int __stdcall Play(DWORD dwReserved1, DWORD dwPriority, DWORD dwFlags) = 0; // 0x30
  virtual int __stdcall SetCurrentPosition(DWORD dwNewPosition) = 0;                  // 0x34
  virtual int __stdcall SetFormat(void* pcfxFormat) = 0;                              // 0x38
  virtual int __stdcall SetVolume(long lVolume) = 0;                                  // 0x3c
  virtual int __stdcall SetPan(long lPan) = 0;                                        // 0x40
  virtual int __stdcall SetFrequency(DWORD dwFrequency) = 0;                          // 0x44
  virtual int __stdcall Stop() = 0;                                                   // 0x48
  virtual int __stdcall Unlock(void* pvAudioPtr1, DWORD dwAudioBytes1, void* pvAudioPtr2,
                               DWORD dwAudioBytes2) = 0; // 0x4c
  virtual int __stdcall Restore() = 0;                   // 0x50
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

#define DSERR_BUFFERLOST 0x88780096

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
class IDirectSound {
public:
  virtual int __stdcall QueryInterface(void* riid, void** ppvObj) = 0; // 0x00
  virtual unsigned long __stdcall AddRef() = 0;                        // 0x04
  virtual unsigned long __stdcall Release() = 0;                       // 0x08
  virtual int __stdcall CreateSoundBuffer(void* pcDSBufferDesc, IDirectSoundBuffer** ppDSBuffer,
                                          void* pUnkOuter) = 0; // 0x0c
  virtual int __stdcall GetCaps(void* pDSCaps) = 0;             // 0x10
  virtual int __stdcall DuplicateSoundBuffer(IDirectSoundBuffer* pDSBufferOriginal,
                                             IDirectSoundBuffer** ppDSBufferDuplicate) = 0; // 0x14
  virtual int __stdcall SetCooperativeLevel(void* hwnd, DWORD dwLevel) = 0;                 // 0x18
  virtual int __stdcall Compact() = 0;                                                      // 0x1c
  virtual int __stdcall GetSpeakerConfig(DWORD* pdwSpeakerConfig) = 0;                      // 0x20
  virtual int __stdcall SetSpeakerConfig(DWORD dwSpeakerConfig) = 0;                        // 0x24
  virtual int __stdcall Initialize(void* pcGuidDevice) = 0;                                 // 0x28
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

#define DSSCL_NORMAL 1

struct DSBUFFERDESC {
  DWORD dwSize;              // 0x00
  DWORD dwFlags;             // 0x04
  DWORD dwBufferBytes;       // 0x08
  DWORD dwReserved;          // 0x0c
  WAVEFORMATEX* lpwfxFormat; // 0x10
};

struct DSBCAPS {
  DWORD dwSize;
  DWORD dwFlags;
  DWORD dwBufferBytes;
  DWORD dwUnlockTransferRate;
  DWORD dwPlayCpuOverhead;
};

class WaveLoadDescriptor {
public:
  DWORD cbWaveSize;          // 0x00 — byte size of the loaded 'data' chunk
  DWORD cSamples;            // 0x04 — sample-count out slot (never filled by the loader)
  WAVEFORMATEX* pwfx;        // 0x08 — GlobalAlloc'd wave format header
  unsigned char* pbWaveData; // 0x0c — GlobalAlloc'd wave data bytes

  WaveLoadDescriptor() : cbWaveSize(0), cSamples(0), pwfx(0), pbWaveData(0) {}
  ~WaveLoadDescriptor() {
    if (pwfx != 0) {
      GlobalFreePtr(pwfx);
    }
    pwfx = 0;
    if (pbWaveData != 0) {
      GlobalFreePtr(pbWaveData);
    }
    pbWaveData = 0;
  }
};

class TSoundResourceManager {
public:
  TSoundResourceManager() : m_device(0), m_module(0) {
    for (int channel = 0; channel < 6; ++channel) {
      m_channels[channel] = 0;
    }
  }
  ~TSoundResourceManager() {
    ReleaseDirectSoundDeviceAndChannels();
  }

  int UpdateLocalizationAudioSlot(int slot);
  int LoadWaveFileByPathAndBuildBuffer(char* filePath, int slot);
  int LoadWaveResourceByNumericIdAndBuildBuffer(unsigned int waveId, int slot);
  int ReadWaveDataAndFormatViaLoaderWithRetry(WaveLoadDescriptor* desc, int slot);
  int SetChannelVolumesUntilAccepted(int volume);
  int SetChannelVolume(int volume, int slot);
  int InitializeDirectSoundDeviceAndChannels();
  void ReleaseDirectSoundDeviceAndChannels();
  int CreateChannelBuffer(IDirectSoundBuffer** ppChannel);

  IDirectSound* m_device;            // 0x00 — DirectSound device object
  IDirectSoundBuffer* m_channels[6]; // 0x04..0x18
  DSBUFFERDESC m_channelBufferDesc;  // 0x1c..0x2f — scratch buffer descriptor (0x24=dwBufferBytes)
  HMODULE m_module;                  // 0x30 (wave-pack module datafile)
  int m_field34;                     // 0x34 (last DirectSound result)
};
