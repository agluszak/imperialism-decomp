#include "game/core/stream_byteswap.h"

#include "game/core/TStream.h"

// Shared byte-order helpers for the big-endian TStream serialization format. These are
// the two shapes the original emits out of line; the inlined shapes live in the header.
// See include/game/core/stream_byteswap.h for which shape to use at a given call site.

// Swap the two bytes of one 16-bit field in place.
// FUNCTION: IMPERIALISM 0x004f2970
void ByteSwapShortInPlace(unsigned char* bytes) {
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
void ReadByteSwappedShortArrayFromStream(TStream* stream, unsigned char* buffer, int shortCount) {
  stream->ReadBytes(buffer, shortCount * 2);
  if (0 < shortCount) {
    unsigned char* cursor = buffer;
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
