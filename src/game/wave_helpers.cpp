#include "game/wave_helpers.h"

#include "game/global_data_tables.h"
#include <stdio.h>

// FUNCTION: IMPERIALISM 0x0047cdd0
int __stdcall ApplyAuxOutputVolumeFromScalar(int scalar) {
  return SetAuxOutputVolumeFromScalar(scalar);
}

// DirectX SDK sample wave.c module (see wave_helpers.h). The three functions below are
// the read-side helpers used by TSoundResourceManager's wave loaders.

// FUNCTION: IMPERIALISM 0x005e0780
UINT OpenWaveMmioReadFmtChunkAndAllocateHeader(char* pszFileName, HMMIO* phmmio,
                                               WAVEFORMATEX** ppwfx, MMCKINFO* pckInRIFF,
                                               MMIOINFO* pmmioInfo) {
  HMMIO hmmio;
  UINT result;
  MMCKINFO ckIn;
  PCMWAVEFORMAT pcmWaveFormat;
  WORD cbExtraAlloc;

  *ppwfx = 0;
  hmmio = mmioOpenA(pszFileName, pmmioInfo, MMIO_ALLOCBUF);
  if (hmmio == 0) {
    result = ER_CANNOTOPEN;
  } else {
    result = mmioDescend(hmmio, pckInRIFF, 0, 0);
    if (result == 0) {
      if (pckInRIFF->ckid == FOURCC_RIFF && pckInRIFF->fccType == mmioFOURCC('W', 'A', 'V', 'E')) {
        ckIn.ckid = mmioFOURCC('f', 'm', 't', ' ');
        result = mmioDescend(hmmio, &ckIn, pckInRIFF, MMIO_FINDCHUNK);
        if (result != 0) {
          goto ErrorReadingWave;
        }
        if (ckIn.cksize >= sizeof(PCMWAVEFORMAT)) {
          if (mmioRead(hmmio, (HPSTR)&pcmWaveFormat, sizeof(pcmWaveFormat)) !=
              sizeof(pcmWaveFormat)) {
            result = ER_CANNOTREAD;
            goto ErrorReadingWave;
          }
          if (pcmWaveFormat.wf.wFormatTag == WAVE_FORMAT_PCM) {
            cbExtraAlloc = 0;
          } else {
            if (mmioRead(hmmio, (HPSTR)&cbExtraAlloc, sizeof(cbExtraAlloc)) !=
                sizeof(cbExtraAlloc)) {
              result = ER_CANNOTREAD;
              goto ErrorReadingWave;
            }
          }
          *ppwfx = (WAVEFORMATEX*)GlobalAlloc(GMEM_FIXED, sizeof(WAVEFORMATEX) + cbExtraAlloc);
          if (*ppwfx == 0) {
            result = ER_MEM;
            goto ErrorReadingWave;
          }
          *(PCMWAVEFORMAT*)*ppwfx = pcmWaveFormat;
          (*ppwfx)->cbSize = cbExtraAlloc;
          if (cbExtraAlloc == 0 || mmioRead(hmmio, (HPSTR)((char*)*ppwfx + sizeof(WAVEFORMATEX)),
                                            cbExtraAlloc) == cbExtraAlloc) {
            result = mmioAscend(hmmio, &ckIn, 0);
            if (result == 0) {
              *phmmio = hmmio;
              return 0;
            }
            goto ErrorReadingWave;
          }
        }
      }
      result = ER_NOTWAVEFILE;
    }
  }
ErrorReadingWave:
  if (*ppwfx != 0) {
    GlobalFree(*ppwfx);
    *ppwfx = 0;
  }
  if (hmmio != 0) {
    mmioClose(hmmio, 0);
  }
  *phmmio = 0;
  return result;
}

// FUNCTION: IMPERIALISM 0x005e09f0
UINT ReadMmioBytesToBufferAndUpdateChunkRemaining(HMMIO hmmio, UINT cbRead, HPSTR pbDest,
                                                  MMCKINFO* pckIn, UINT* pcbActualRead) {
  MMIOINFO mmioinfoIn;
  UINT cT;
  UINT result;

  result = mmioGetInfo(hmmio, &mmioinfoIn, 0) != 0;
  if (result == 0) {
    if (pckIn->cksize < cbRead) {
      cbRead = pckIn->cksize;
    }
    pckIn->cksize = pckIn->cksize - cbRead;
    for (cT = 0; cT < cbRead; ++cT) {
      if (mmioinfoIn.pchNext == mmioinfoIn.pchEndRead) {
        result = mmioAdvance(hmmio, &mmioinfoIn, 0);
        if (result != 0) {
          *pcbActualRead = 0;
          return result;
        }
        if (mmioinfoIn.pchNext == mmioinfoIn.pchEndRead) {
          *pcbActualRead = 0;
          return ER_CORRUPTWAVEFILE;
        }
      }
      pbDest[cT] = *mmioinfoIn.pchNext++;
    }
    result = mmioSetInfo(hmmio, &mmioinfoIn, 0);
    if (result == 0) {
      *pcbActualRead = cbRead;
      return 0;
    }
  }
  *pcbActualRead = 0;
  return result;
}

// FUNCTION: IMPERIALISM 0x005e0b50
UINT CreateWaveFileAndWriteFmtFactChunks(char* pszFileName, HMMIO* phmmioOut,
                                         WAVEFORMATEX* pwfxDest, MMCKINFO* pckOut,
                                         MMCKINFO* pckOutRIFF) {
  DWORD dwFactChunk;
  UINT result;
  MMCKINFO ckOutFact;

  dwFactChunk = (DWORD)-1;
  *phmmioOut = mmioOpenA(pszFileName, 0, MMIO_ALLOCBUF | MMIO_READWRITE | MMIO_CREATE);
  if (*phmmioOut != 0) {
    pckOutRIFF->fccType = mmioFOURCC('W', 'A', 'V', 'E');
    pckOutRIFF->cksize = 0;
    result = mmioCreateChunk(*phmmioOut, pckOutRIFF, MMIO_CREATERIFF);
    if (result != 0) {
      return result;
    }
    pckOut->ckid = mmioFOURCC('f', 'm', 't', ' ');
    pckOut->cksize = sizeof(PCMWAVEFORMAT);
    result = mmioCreateChunk(*phmmioOut, pckOut, 0);
    if (result != 0) {
      return result;
    }
    if (pwfxDest->wFormatTag == WAVE_FORMAT_PCM) {
      if (mmioWrite(*phmmioOut, (char*)pwfxDest, sizeof(PCMWAVEFORMAT)) != sizeof(PCMWAVEFORMAT)) {
        return ER_CANNOTWRITE;
      }
    } else {
      if (mmioWrite(*phmmioOut, (char*)pwfxDest, sizeof(WAVEFORMATEX) + pwfxDest->cbSize) !=
          sizeof(WAVEFORMATEX) + pwfxDest->cbSize) {
        return ER_CANNOTWRITE;
      }
    }
    result = mmioAscend(*phmmioOut, pckOut, 0);
    if (result != 0) {
      return result;
    }
    ckOutFact.ckid = mmioFOURCC('f', 'a', 'c', 't');
    result = mmioCreateChunk(*phmmioOut, &ckOutFact, 0);
    if (result != 0) {
      return result;
    }
    if (mmioWrite(*phmmioOut, (char*)&dwFactChunk, sizeof(dwFactChunk)) == sizeof(dwFactChunk) &&
        mmioAscend(*phmmioOut, &ckOutFact, 0) == 0) {
      return 0;
    }
  }
  return ER_CANNOTWRITE;
}

// FUNCTION: IMPERIALISM 0x005e0fb0
int CopyMmioChunkByFourCCViaGlobalBuffer(HMMIO hmmioIn, HMMIO hmmioOut, MMCKINFO* pckIn) {
  HGLOBAL hMem;
  HPSTR pch;
  MMCKINFO ckOut;

  hMem = GlobalAlloc(GHND, pckIn->cksize);
  pch = (HPSTR)GlobalLock(hMem);
  if (pch == 0) {
    return 0;
  }
  ckOut.ckid = pckIn->ckid;
  ckOut.cksize = pckIn->cksize;
  if (mmioCreateChunk(hmmioOut, &ckOut, 0) == 0) {
    if ((DWORD)mmioRead(hmmioIn, pch, pckIn->cksize) == pckIn->cksize) {
      if ((DWORD)mmioWrite(hmmioOut, pch, pckIn->cksize) == pckIn->cksize) {
        if (mmioAscend(hmmioOut, &ckOut, 0) == 0) {
          GlobalUnlock(GlobalHandle(pch));
          GlobalFree(GlobalHandle(pch));
          return 1;
        }
      }
    }
  }
  GlobalUnlock(GlobalHandle(pch));
  GlobalFree(GlobalHandle(pch));
  return 0;
}

// FUNCTION: IMPERIALISM 0x005e10c0
UINT LoadWaveDataAndFormatFromFilePath(char* pszFileName, DWORD* pcbSize, DWORD* pcSamples,
                                       WAVEFORMATEX** ppwfx, unsigned char** ppbData,
                                       MMIOINFO* pmmioInfo) {
  HMMIO hmmio;
  UINT result;
  UINT cbActualRead;
  MMCKINFO ckIn;
  MMCKINFO ckInRIFF;

  *ppbData = 0;
  *ppwfx = 0;
  *pcbSize = 0;
  result =
      OpenWaveMmioReadFmtChunkAndAllocateHeader(pszFileName, &hmmio, ppwfx, &ckInRIFF, pmmioInfo);
  if (result == 0) {
    mmioSeek(hmmio, ckInRIFF.dwDataOffset + sizeof(FOURCC), SEEK_SET);
    ckIn.ckid = mmioFOURCC('d', 'a', 't', 'a');
    result = mmioDescend(hmmio, &ckIn, &ckInRIFF, MMIO_FINDCHUNK);
    if (result == 0) {
      *ppbData = (unsigned char*)GlobalAlloc(GMEM_FIXED, ckIn.cksize);
      if (*ppbData == 0) {
        result = ER_MEM;
      } else {
        result = ReadMmioBytesToBufferAndUpdateChunkRemaining(hmmio, ckIn.cksize, (HPSTR)*ppbData,
                                                              &ckIn, &cbActualRead);
        if (result == 0) {
          *pcbSize = cbActualRead;
          goto CloseAndReturn;
        }
      }
    }
  }
  if (*ppbData != 0) {
    GlobalFree(*ppbData);
    *ppbData = 0;
  }
  if (*ppwfx != 0) {
    GlobalFree(*ppwfx);
    *ppwfx = 0;
  }
CloseAndReturn:
  if (hmmio != 0) {
    mmioClose(hmmio, 0);
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005e1500
int __stdcall SetAuxOutputVolumeFromScalar(int scalar) {
  if (g_nAuxOutputDeviceIndex == -1) {
    return 0;
  }
  auxSetVolume(g_nAuxOutputDeviceIndex, (scalar << 16) + scalar);
  return 1;
}

// FUNCTION: IMPERIALISM 0x005e1590
bool __stdcall SetAuxOutputVolumeAcrossCompatibleDevices(int level) {
  MMRESULT result = 0;
  UINT numDevs = auxGetNumDevs();
  UINT deviceId = 0;
  if (0 < static_cast<int>(numDevs)) {
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
