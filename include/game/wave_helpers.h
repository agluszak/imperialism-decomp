#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

#include <mmsystem.h>

// Wave-file loading helpers — the DirectX SDK sample wave.c module statically linked at
// 0x5e0780..0x5e11c6. Free __cdecl functions (every callsite is caller-cleaned).
// Still stubbed from the same module: CreateWaveFileAndWriteFmtFactChunks (0x5e0b50) and
// CopyMmioChunkByFourCCViaGlobalBuffer (0x5e0fb0).

// wave.c ER_* error codes.
#define ER_MEM 0xe000
#define ER_CANNOTOPEN 0xe100
#define ER_NOTWAVEFILE 0xe101
#define ER_CANNOTREAD 0xe102
#define ER_CORRUPTWAVEFILE 0xe103

// 0x005e0780 — wave.c WaveOpenFile: mmioOpen the file (or memory file via pmmioInfo),
// verify RIFF/WAVE, read the 'fmt ' chunk into a GlobalAlloc'd WAVEFORMATEX.
UINT OpenWaveMmioReadFmtChunkAndAllocateHeader(char* pszFileName, HMMIO* phmmio,
                                               WAVEFORMATEX** ppwfx, MMCKINFO* pckInRIFF,
                                               MMIOINFO* pmmioInfo);

// 0x005e09f0 — wave.c WaveReadFile: stream up to cbRead bytes of the current chunk into
// pbDest through the mmio buffer, decrementing pckIn->cksize.
UINT ReadMmioBytesToBufferAndUpdateChunkRemaining(HMMIO hmmio, UINT cbRead, HPSTR pbDest,
                                                  MMCKINFO* pckIn, UINT* pcbActualRead);

// 0x005e10c0 — wave.c WaveLoadFile: open, locate 'data', GlobalAlloc and read the wave
// bytes; outputs format header, data pointer and byte size. pcSamples is never written.
UINT LoadWaveDataAndFormatFromFilePath(char* pszFileName, DWORD* pcbSize, DWORD* pcSamples,
                                       WAVEFORMATEX** ppwfx, unsigned char** ppbData,
                                       MMIOINFO* pmmioInfo);
