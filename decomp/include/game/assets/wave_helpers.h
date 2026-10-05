#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

#include <mmsystem.h>

// The Microsoft DirectX SDK sample wave.c module, compiled directly into this game (not a
// linked prebuilt library -- there is no separate wave.lib to pair against, so these bodies
// are ported like game code even though the source itself is Microsoft's, not Imperialism's).
// Statically linked at 0x5e0780..0x5e11c6. Free __cdecl functions (every callsite is
// caller-cleaned). Function names below are the sample's real, published identifiers
// (WaveOpenFile/WaveReadFile/WaveCreateFile/WaveLoadFile), not invented descriptive ones --
// confirmed both by structural comparison against the well-known sample source and by this
// header's own prior comments, which already named them correctly in prose.

// wave.c ER_* error codes.
#define ER_MEM 0xe000
#define ER_CANNOTOPEN 0xe100
#define ER_NOTWAVEFILE 0xe101
#define ER_CANNOTREAD 0xe102
#define ER_CORRUPTWAVEFILE 0xe103
#define ER_CANNOTWRITE 0xe104

UINT WaveOpenFile(char* pszFileName, HMMIO* phmmio, WAVEFORMATEX** ppwfx, MMCKINFO* pckInRIFF,
                  MMIOINFO* pmmioInfo);

// 0x005e09a0 — seek to the RIFF payload and descend into its 'data' chunk.
UINT WaveStartDataRead(HMMIO* phmmioIn, MMCKINFO* pckIn, MMCKINFO* pckInRIFF);

UINT WaveReadFile(HMMIO hmmio, UINT cbRead, HPSTR pbDest, MMCKINFO* pckIn, UINT* pcbActualRead);

// 0x005e0b00 — release the format block and close the input file.
UINT WaveCloseReadFile(HMMIO* phmmio, WAVEFORMATEX** ppwfx);

UINT WaveLoadFile(char* pszFileName, DWORD* pcbSize, DWORD* pcSamples, WAVEFORMATEX** ppwfx,
                  unsigned char** ppbData, MMIOINFO* pmmioInfo);

UINT WaveCreateFile(char* pszFileName, HMMIO* phmmioOut, WAVEFORMATEX* pwfxDest, MMCKINFO* pckOut,
                    MMCKINFO* pckOutRIFF);

// 0x005e0cc0 — create an empty 'data' chunk and acquire its write-buffer state.
UINT WaveStartDataWrite(HMMIO* phmmioOut, MMCKINFO* pckOut, MMIOINFO* pmmioinfoOut);

UINT WaveWriteFile(HMMIO hmmioOut, UINT cbWrite, BYTE* pbSrc, MMCKINFO* pck, UINT* pcbWritten,
                   MMIOINFO* pmmioinfo);

UINT WaveCloseWriteFile(HMMIO* phmmio, MMCKINFO* pck, MMCKINFO* pckRIFF, MMIOINFO* pmmioinfo,
                        DWORD cSamples);

UINT WaveCopyUselessChunks(HMMIO* phmmioIn, MMCKINFO* pckIn, MMCKINFO* pckInRIFF, HMMIO* phmmioOut);

int WaveCopyUselessChunk(HMMIO hmmioIn, HMMIO hmmioOut, MMCKINFO* pckIn);

UINT WaveSaveFile(char* pszFileName, DWORD cbSize, DWORD cSamples, WAVEFORMATEX* pwfxDest,
                  HPSTR pbSrc);
