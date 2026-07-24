#include "game/assets/wave_helpers.h"
#include "game/globals/assets_globals.h"

#include <stdio.h>

// FUNCTION: IMPERIALISM 0x005e0780
UINT WaveOpenFile(char* pszFileName, HMMIO* phmmio, WAVEFORMATEX** ppwfx, MMCKINFO* pckInRIFF,
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
UINT WaveReadFile(HMMIO hmmio, UINT cbRead, HPSTR pbDest, MMCKINFO* pckIn, UINT* pcbActualRead) {
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
UINT WaveCreateFile(char* pszFileName, HMMIO* phmmioOut, WAVEFORMATEX* pwfxDest, MMCKINFO* pckOut,
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
UINT WaveLoadFile(char* pszFileName, DWORD* pcbSize, DWORD* pcSamples, WAVEFORMATEX** ppwfx,
                  unsigned char** ppbData, MMIOINFO* pmmioInfo) {
  HMMIO hmmio;
  UINT result;
  UINT cbActualRead;
  MMCKINFO ckIn;
  MMCKINFO ckInRIFF;

  *ppbData = 0;
  *ppwfx = 0;
  *pcbSize = 0;
  result = WaveOpenFile(pszFileName, &hmmio, ppwfx, &ckInRIFF, pmmioInfo);
  if (result == 0) {
    mmioSeek(hmmio, ckInRIFF.dwDataOffset + sizeof(FOURCC), SEEK_SET);
    ckIn.ckid = mmioFOURCC('d', 'a', 't', 'a');
    result = mmioDescend(hmmio, &ckIn, &ckInRIFF, MMIO_FINDCHUNK);
    if (result == 0) {
      *ppbData = (unsigned char*)GlobalAlloc(GMEM_FIXED, ckIn.cksize);
      if (*ppbData == 0) {
        result = ER_MEM;
      } else {
        result = WaveReadFile(hmmio, ckIn.cksize, (HPSTR)*ppbData, &ckIn, &cbActualRead);
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

// Selects the aux output device whose product-id low 3 bits are 1 or 2 (the CD-audio line),
// storing its index in g_nAuxOutputDeviceIndex (-1 on a device-caps query error).
// FUNCTION: IMPERIALISM 0x005e1430
int ProbeAuxOutputDeviceIndexByPidMask() {
  MMRESULT capsResult = 0;
  UINT deviceCount = auxGetNumDevs();
  int deviceId = 0;
  if (static_cast<int>(deviceCount) > 0) {
    AUXCAPSA caps;
    do {
      capsResult = auxGetDevCapsA(deviceId, &caps, sizeof(AUXCAPSA));
      if ((caps.wPid & 7) == 1 || (caps.wPid & 7) == 2) {
        g_nAuxOutputDeviceIndex = deviceId;
        break;
      }
      deviceId++;
    } while (deviceId < static_cast<int>(deviceCount));
  }
  if (capsResult != 0) {
    g_nAuxOutputDeviceIndex = -1;
    return 0;
  }
  return 1;
}
