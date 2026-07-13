#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

#include <mmsystem.h>

// Wave-file loading helpers — the DirectX SDK sample wave.c module statically linked at
// 0x5e0780..0x5e11c6. Free __cdecl functions (every callsite is caller-cleaned).

// wave.c ER_* error codes.
#define ER_MEM 0xe000
#define ER_CANNOTOPEN 0xe100
#define ER_NOTWAVEFILE 0xe101
#define ER_CANNOTREAD 0xe102
#define ER_CORRUPTWAVEFILE 0xe103
#define ER_CANNOTWRITE 0xe104

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

// 0x005e0b50 — wave.c WaveCreateFile: create the output file, write the RIFF/WAVE header,
// the 'fmt ' chunk (from pwfxDest), and a placeholder 'fact' chunk (dwFactChunk = -1).
UINT CreateWaveFileAndWriteFmtFactChunks(char* pszFileName, HMMIO* phmmioOut,
                                         WAVEFORMATEX* pwfxDest, MMCKINFO* pckOut,
                                         MMCKINFO* pckOutRIFF);

// 0x005e0fb0 — wave.c helper: copy one chunk (pckIn->ckid/cksize) from hmmioIn to hmmioOut
// through a GlobalAlloc'd bounce buffer. Returns 1 on success, 0 on failure.
int CopyMmioChunkByFourCCViaGlobalBuffer(HMMIO hmmioIn, HMMIO hmmioOut, MMCKINFO* pckIn);

// Aux-output (CD-audio line) volume: 0x69b89c holds the probed aux device index
// (-1 = none found; set by ProbeAuxOutputDeviceIndexByPidMask 0x5e1430, unported).
// Duplicates dwVolume into both channel words and calls winmm auxSetVolume.
int __stdcall SetAuxOutputVolumeFromScalar(int scalar);
// 0x5e1590: sets volume on every aux device whose wPid&7 is 1 or 2; returns whether the
// last auxGetDevCaps call succeeded.
bool __stdcall SetAuxOutputVolumeAcrossCompatibleDevices(int level); // 0x5e1500
// Thin forwarder (multimedia module copy at 0x47cdd0).
int __stdcall ApplyAuxOutputVolumeFromScalar(int scalar); // 0x47cdd0
