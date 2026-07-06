#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

#include <mmsystem.h>
#include <windowsx.h>

// Global sound/wave resource manager living at 0x006a60c0. It owns an array of six
// DirectSound secondary-buffer channels (+0x04..+0x18), the channel buffer byte size
// (+0x24), the wave-pack module handle (+0x30) and a scratch result slot (+0x34).

// The six channel objects are real COM IDirectSoundBuffer instances. dsound.h is not part
// of the MSVC500 toolchain, so the interface is declared here with the retail vtable
// layout. ABI verified in the disassembly: every call pushes the interface pointer itself
// (COM `__stdcall` this-on-stack, e.g. 0x49c240 `PUSH EAX / CALL [ECX+0x34]`), slot 0x2c
// takes the 7 Lock arguments, and 0x49c720 retries a failed Lock after DSERR_BUFFERLOST
// (0x88780096) with a slot-0x50 Restore — the IDirectSoundBuffer slot map exactly.
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

#define DSERR_BUFFERLOST 0x88780096

// The DirectSound device object (0x00). Hand-declared with the retail IDirectSound vtable
// layout for the same reason as IDirectSoundBuffer above (dsound.h is kept out of these
// TUs). Only CreateSoundBuffer (0x0c) and SetCooperativeLevel (0x18) are called here.
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

#define DSSCL_NORMAL 1

// DSBUFFERDESC / DSBCAPS — hand-declared to match dsound.h layout (kept out of this TU).
// The manager keeps a persistent DSBUFFERDESC scratch inside its own fields (0x1c..0x2f);
// dwBufferBytes (+0x24) is the byte size every channel buffer is created (and later
// Lock'd) with.
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

// Stack-local wave-load result block shared by the loaders (0x49c290/0x49c430) and
// ReadWaveDataAndFormatViaLoaderWithRetry (0x49c720). A real local class in the original:
// both loaders carry an EH state for it and run an inlined destructor (windowsx.h
// GlobalFreePtr pairs — GlobalUnlock + GlobalFree via GlobalHandle) on every exit path.
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
  }
};

class TSoundResourceManager {
public:
  // 0x0049c240 — rewind channel `slot` to position 0 and (re)start playback.
  int UpdateLocalizationAudioSlot(int slot);
  // 0x0049c290 — load a wave file by path and copy it into channel `slot`'s buffer.
  int LoadWaveFileByPathAndBuildBuffer(char* filePath, int slot);
  // 0x0049c430 — load wave `waveId` from "<id>.wav" or the wave-pack module's "WAVE"
  // resource (via the 'MEM ' mmio proc) and copy it into channel `slot`'s buffer.
  int LoadWaveResourceByNumericIdAndBuildBuffer(unsigned int waveId, int slot);
  // 0x0049c720 — Lock channel `slot`'s DirectSound buffer (Restore+retry on
  // DSERR_BUFFERLOST), copy the loaded wave data in, zero-fill the tail, Unlock.
  int ReadWaveDataAndFormatViaLoaderWithRetry(WaveLoadDescriptor* desc, int slot);
  // 0x0049c850 — push `volume` to every channel until one accepts it.
  int SetChannelVolumesUntilAccepted(int volume);
  // 0x0049c970 — create the DirectSound device (once), set the app main-window cooperative
  // level, then create all six channel buffers. Returns 1 on success, 0 on failure.
  int InitializeDirectSoundDeviceAndChannels();
  // 0x0049c150 — build the shared DSBUFFERDESC and create one channel buffer into
  // *ppChannel, then GetCaps to confirm it. Returns 1 on success, 0 on failure.
  int CreateChannelBuffer(IDirectSoundBuffer** ppChannel);

  IDirectSound* m_device;            // 0x00 — DirectSound device object
  IDirectSoundBuffer* m_channels[6]; // 0x04..0x18
  DSBUFFERDESC m_channelBufferDesc;  // 0x1c..0x2f — scratch buffer descriptor (0x24=dwBufferBytes)
  HMODULE m_module;                  // 0x30 (wave-pack module datafile)
  int m_field34;                     // 0x34 (last DirectSound result)
};
