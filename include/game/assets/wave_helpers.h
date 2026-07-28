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

// 0x005e0780 — mmioOpen the file (or memory file via pmmioInfo), verify RIFF/WAVE, read the
// 'fmt ' chunk into a GlobalAlloc'd WAVEFORMATEX.
UINT WaveOpenFile(char* pszFileName, HMMIO* phmmio, WAVEFORMATEX** ppwfx, MMCKINFO* pckInRIFF,
                  MMIOINFO* pmmioInfo);

// 0x005e09f0 — stream up to cbRead bytes of the current chunk into pbDest through the mmio
// buffer, decrementing pckIn->cksize.
UINT WaveReadFile(HMMIO hmmio, UINT cbRead, HPSTR pbDest, MMCKINFO* pckIn, UINT* pcbActualRead);

// 0x005e10c0 — open, locate 'data', GlobalAlloc and read the wave bytes; outputs format
// header, data pointer and byte size. pcSamples is never written.
UINT WaveLoadFile(char* pszFileName, DWORD* pcbSize, DWORD* pcSamples, WAVEFORMATEX** ppwfx,
                  unsigned char** ppbData, MMIOINFO* pmmioInfo);

// 0x005e0b50 — create the output file, write the RIFF/WAVE header, the 'fmt ' chunk (from
// pwfxDest), and a placeholder 'fact' chunk (dwFactChunk = -1).
// Flush the write buffer, close both chunks, then reopen the 'fact' chunk to patch in the
// real sample count WaveCreateFile could only write as a placeholder, and close the file.
// 0x005e0da0.
UINT WaveCloseWriteFile(HMMIO* phmmio, MMCKINFO* pck, MMCKINFO* pckRIFF, MMIOINFO* pmmioinfo,
                        DWORD cSamples);

UINT WaveCreateFile(char* pszFileName, HMMIO* phmmioOut, WAVEFORMATEX* pwfxDest, MMCKINFO* pckOut,
                    MMCKINFO* pckOutRIFF);

// 0x005e0fb0 — copy one chunk (pckIn->ckid/cksize) from hmmioIn to hmmioOut through a
// GlobalAlloc'd bounce buffer. Returns 1 on success, 0 on failure. Real original name not
// independently confirmed (kept descriptive rather than guessed).
int CopyMmioChunkByFourCCViaGlobalBuffer(HMMIO hmmioIn, HMMIO hmmioOut, MMCKINFO* pckIn);
