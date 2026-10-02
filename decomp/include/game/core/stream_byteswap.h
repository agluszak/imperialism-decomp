#pragma once

#include "compat.h"

#include "game/core/TStream.h"

// TStream moves bytes without changing their big-endian serialized representation.
void ByteSwapShortInPlace(short* value);      // 0x004f2970
void SwapFirstTwoBytesInBuffer(short* value); // 0x004b9340

void ReadByteSwappedShortArrayFromStream(TStream* stream, short* values, int shortCount);
void WriteByteSwappedShortArrayToStream(TStream* stream, short* words, int count);
void SwapShortArrayBytes(void* base, int count);
void ReverseDwordArrayBytes(void* base, int count);
void WriteShortArrayElems(TStream* stream, const short* values, int count);
void WriteShortArrayElemsRev(TStream* stream, const short* values, int count);
void WriteFloatArrayElems(TStream* stream, const float* values, int count);
void WriteIntArrayElems(TStream* stream, const int* values, int count);
