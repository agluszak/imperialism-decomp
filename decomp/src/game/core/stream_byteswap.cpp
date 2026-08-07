#include "game/core/stream_byteswap.h"

#include "game/core/TStream.h"

// Shared byte-order helpers for the big-endian TStream serialization format. These are
// the shapes the original emits out of line; the inlined shapes live in the header.
// See include/game/core/stream_byteswap.h for which shape to use at a given call site.
//
// Bodies are ordered by address (decomplint requires ascending markers), which
// interleaves the read-side and write-side pairs:
//   0x004b9340 SwapFirstTwoBytesInBuffer            (write-side swap)
//   0x004b94a0 WriteByteSwappedShortArrayToStream   (write-side array)
//   0x004f2970 ByteSwapShortInPlace                 (read-side swap; twin of 0x4b9340)
//   0x004f2a60 ReadByteSwappedShortArrayFromStream  (read-side array)

// Byte-identical twin of ByteSwapShortInPlace at a second address: the original emits one
// copy per module that uses the helper, so the image carries two bodies for one source
// function. Kept as two separately-named definitions because a marker binds to exactly
// one address; the write path calls this one.
// FUNCTION: IMPERIALISM 0x004b9340
void SwapFirstTwoBytesInBuffer(short* value) {
  unsigned char* buffer = static_cast<unsigned char*>(static_cast<void*>(value));
  unsigned char tmp = buffer[0];
  buffer[0] = buffer[1];
  buffer[1] = tmp;
}

// Copy each short into a 2-byte scratch, swap it to the stream's big-endian order, and
// push it through the WriteBytes primitive (slot 0x78). The swap is inlined at this
// site in the original even though SwapFirstTwoBytesInBuffer exists.
// (Previously named WriteWordArrayToOutputCallbackLE -- the stream order is big-endian,
// so the "LE" in that name was backwards.)
// FUNCTION: IMPERIALISM 0x004b94a0
void WriteByteSwappedShortArrayToStream(TStream* stream, short* words, int count) {
  for (; count > 0; --count) {
    unsigned short buffer = static_cast<unsigned short>(*words);
    unsigned char* bytes = static_cast<unsigned char*>(static_cast<void*>(&buffer));
    unsigned char tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = tmp;
    stream->WriteBytes(&buffer, 2);
    ++words;
  }
}

// Swap the two bytes of one 16-bit field in place.
// FUNCTION: IMPERIALISM 0x004f2970
void ByteSwapShortInPlace(short* value) {
  unsigned char* bytes = static_cast<unsigned char*>(static_cast<void*>(value));
  unsigned char firstByte = bytes[0];
  unsigned char secondByte = bytes[1];
  bytes[0] = secondByte;
  bytes[1] = firstByte;
}

// Read `shortCount` big-endian shorts from `stream` into `buffer` and byte-swap each pair
// in place, so the caller ends up with host-order shorts. A zero or negative count reads
// nothing back-to-front and skips the swap loop entirely. The loop walks a separate
// cursor rather than advancing `buffer`, matching the original's register use.
// FUNCTION: IMPERIALISM 0x004f2a60
void ReadByteSwappedShortArrayFromStream(TStream* stream, short* values, int shortCount) {
  stream->ReadBytes(values, shortCount * 2);
  if (0 < shortCount) {
    unsigned char* cursor = static_cast<unsigned char*>(static_cast<void*>(values));
    do {
      unsigned char firstByte = cursor[0];
      unsigned char secondByte = cursor[1];
      cursor[0] = secondByte;
      cursor[1] = firstByte;
      cursor = cursor + 2;
      shortCount = shortCount - 1;
    } while (shortCount != 0);
  }
}
