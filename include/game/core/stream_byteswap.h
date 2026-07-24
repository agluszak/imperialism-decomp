#pragma once

#include "compat.h"

#include "game/core/TStream.h"

// Byte-order helpers for the TStream save/network serialization format.
//
// The stream format is BIG-ENDIAN (the Windows build shares its persisted format with
// the Macintosh original), so every 16/32-bit field has to be swapped around the raw
// block read/write primitives -- TStream itself moves bytes only (ReadBytes slot 0x3c,
// WriteBytesSlot78 slot 0x78) and does no reordering.
//
// Two shapes appear in the original image and both are reproduced here:
//
//   * Out-of-line calls to the shared helpers below (ByteSwapShortInPlace 0x004f2970,
//     ReadByteSwappedShortArrayFromStream 0x004f2a60). Use these where the listing shows
//     a CALL to those addresses (directly or through an ILT thunk).
//   * Swap loops inlined into the serializer itself. Use the `static __inline` helpers
//     below for those: each translation unit inlines them at the call site so no symbol
//     is emitted, matching the original's per-element loops.
//
// Pick the shape the listing shows for the call site being ported. Forcing an inlined
// site through the out-of-line helper (or vice versa) changes codegen and costs match.

// FUNCTION-adjacent: the real image symbol lives in src/game/core/stream_byteswap.cpp.
void ByteSwapShortInPlace(unsigned char* bytes);

// Reads `shortCount` big-endian shorts through the stream's ReadBytes primitive and
// swaps each pair in place, leaving the caller with host-order shorts.
void ReadByteSwappedShortArrayFromStream(TStream* stream, unsigned char* buffer, int shortCount);

// ---------------------------------------------------------------------------
// Inlined shapes (no emitted symbol).
// ---------------------------------------------------------------------------

// Read-side fixup applied after a block ReadBytes of a short array.
static __inline void SwapShortArrayBytes(void* base, int count) {
  unsigned char* bytes = static_cast<unsigned char*>(base);
  int i = 0;
  while (i < count) {
    unsigned char t = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = t;
    bytes += 2;
    ++i;
  }
}

// Read-side fixup applied after a block ReadBytes of a 32-bit array.
static __inline void ReverseDwordArrayBytes(void* base, int count) {
  unsigned char* bytes = static_cast<unsigned char*>(base);
  int i = 0;
  while (i < count) {
    unsigned char t0 = bytes[0];
    unsigned char t1 = bytes[1];
    bytes[0] = bytes[3];
    bytes[1] = bytes[2];
    bytes[2] = t1;
    bytes[3] = t0;
    bytes += 4;
    ++i;
  }
}

// 32-bit swap through a float, for the float-valued fields (mission equipage weights).
static __inline float SwapFloat(float value) {
  union {
    float f;
    unsigned char b[4];
  } swapped;
  swapped.f = value;
  unsigned char byte0 = swapped.b[0];
  unsigned char byte1 = swapped.b[1];
  swapped.b[0] = swapped.b[3];
  swapped.b[1] = swapped.b[2];
  swapped.b[2] = byte1;
  swapped.b[3] = byte0;
  return swapped.f;
}

// Write-side: copy each element into a stack temp, swap it to the stream's byte order and
// write it through the WriteBytesSlot78 primitive (slot 0x78).
static __inline void WriteShortArrayElems(TStream* stream, const short* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    short element = *values;
    unsigned char* elementBytes = reinterpret_cast<unsigned char*>(&element);
    unsigned char low = elementBytes[0];
    elementBytes[0] = elementBytes[1];
    elementBytes[1] = low;
    stream->WriteBytesSlot78(&element, 2);
    ++values;
  }
}

// Variant for sites where the original swapped via the high byte temp first (reads b[1]
// then b[0] -- e.g. TGreatPower::WriteTo's 0x8d6 loop).
static __inline void WriteShortArrayElemsRev(TStream* stream, const short* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    short element = *values;
    unsigned char* elementBytes = reinterpret_cast<unsigned char*>(&element);
    unsigned char high = elementBytes[1];
    unsigned char low = elementBytes[0];
    elementBytes[0] = high;
    elementBytes[1] = low;
    stream->WriteBytesSlot78(&element, 2);
    ++values;
  }
}

static __inline void WriteIntArrayElems(TStream* stream, const int* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    int element = *values;
    unsigned char* elementBytes = reinterpret_cast<unsigned char*>(&element);
    unsigned char b0 = elementBytes[0];
    unsigned char b1 = elementBytes[1];
    elementBytes[0] = elementBytes[3];
    elementBytes[1] = elementBytes[2];
    elementBytes[2] = b1;
    elementBytes[3] = b0;
    stream->WriteBytesSlot78(&element, 4);
    ++values;
  }
}
