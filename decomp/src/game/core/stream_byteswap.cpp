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

// FUNCTION: IMPERIALISM 0x004b9340
void SwapFirstTwoBytesInBuffer(short* value) {
  unsigned char* buffer = static_cast<unsigned char*>(static_cast<void*>(value));
  unsigned char tmp = buffer[0];
  buffer[0] = buffer[1];
  buffer[1] = tmp;
}

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
      cursor += 2;
      --shortCount;
    } while (shortCount != 0);
  }
}

void SwapShortArrayBytes(void* base, int count) {
  unsigned char* bytes = static_cast<unsigned char*>(base);
  for (int i = 0; i < count; ++i) {
    unsigned char value = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = value;
    bytes += 2;
  }
}

void ReverseDwordArrayBytes(void* base, int count) {
  unsigned char* bytes = static_cast<unsigned char*>(base);
  for (int i = 0; i < count; ++i) {
    unsigned char byte0 = bytes[0];
    unsigned char byte1 = bytes[1];
    bytes[0] = bytes[3];
    bytes[1] = bytes[2];
    bytes[2] = byte1;
    bytes[3] = byte0;
    bytes += 4;
  }
}

void WriteShortArrayElems(TStream* stream, const short* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    short value = *values++;
    SwapFirstTwoBytesInBuffer(&value);
    stream->WriteBytes(&value, 2);
  }
}

void WriteShortArrayElemsRev(TStream* stream, const short* values, int count) {
  WriteShortArrayElems(stream, values, count);
}

void WriteFloatArrayElems(TStream* stream, const float* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    float value = *values++;
    ReverseDwordArrayBytes(&value, 1);
    stream->WriteBytes(&value, 4);
  }
}

void WriteIntArrayElems(TStream* stream, const int* values, int count) {
  for (int remaining = count; remaining != 0; --remaining) {
    int value = *values++;
    ReverseDwordArrayBytes(&value, 1);
    stream->WriteBytes(&value, 4);
  }
}
