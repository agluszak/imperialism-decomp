#pragma once

#include "compat.h"
#include "game/mfc.h"
#include "game/stretch.h"

struct StrategicMapOpcodeByteStretchTag {};

// The original one-slot stretch vtables contain Add only; destruction is statically dispatched
// as part of StrategicMapCallbackRecord's member teardown.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x006404a4
class StrategicMapOpcodeByteStretch
    : public stretch<unsigned char, StrategicMapOpcodeByteStretchTag> {
public:
  unsigned char* Add(unsigned char value) override;
  void OverStretch(unsigned int requestedCount);
  unsigned char& operator[](unsigned int index);
};

struct StrategicMapCursorStretchTag {};

// VTABLE: IMPERIALISM 0x006404a8
class StrategicMapCursorStretch : public stretch<int, StrategicMapCursorStretchTag> {
public:
  int* Add(int value) override;
  void OverStretch(unsigned int requestedCount);
  int& operator[](unsigned int index);
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

ASSERT_SIZE(StrategicMapOpcodeByteStretch, 0x10);
ASSERT_SIZE(StrategicMapCursorStretch, 0x10);

struct StrategicMapCallbackRecord {
  StrategicMapCallbackRecord();
  ~StrategicMapCallbackRecord();

  void AppendPackedColorDword(unsigned char* destinationPixels, int packedColor);
  StrategicMapCallbackRecord* AppendOpcodeByte(int value); // returns this (original mov eax,esi)
  void AppendOpcodeBytePair(int value);
  void FinalizeOpcodeBufferAlignment();
  void BuildBitmapMaskOpcodeBufferFromResourceRows(int resourceId, short width, short height,
                                                   int destinationRowStride,
                                                   unsigned char transparentPixel);
  // Apply generated sparse writes to a destination pixel buffer. The retail build executes the
  // x86 stream directly; interpreting its small opcode vocabulary keeps the recovered source
  // portable and avoids inline assembly while preserving the mask semantics.
  void ApplyBitmapMaskToPixelBuffer(unsigned char* destinationPixels);
  void ApplyPackedColorToPixelBuffer(unsigned char* destinationPixels);

  StrategicMapOpcodeByteStretch opcodeBytes00;
  // AppendOpcodeByte's private write cursor is distinct from opcodeBytes00's count because
  // indexed writes can extend the container independently.
  int opcodeAppendCursor10;
  // Rolling modulo-four offset used while aligning the generated opcode stream.
  int opcodeAlignmentOffset14;
  int hadTrailingPadding18;
  StrategicMapCursorStretch packedColorCursor1c;
  // Byte stride used when converting each resource pixel's (x,y) coordinate into its
  // destination-tile offset. No read site outside mask construction.
  int destinationRowStride2c;
};

ASSERT_SIZE(StrategicMapCallbackRecord, 0x30);
