#include "game/wave_helpers.h"

#include <stdio.h>

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
