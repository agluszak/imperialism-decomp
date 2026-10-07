#pragma once

#include "compat.h"
#include "game/mfc.h"
#include "game/stretch.h"

struct DiplomacyMaskBufferRun;
struct TQuickDrawSurfaceContext;

IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR

// VTABLE: IMPERIALISM 0x006404a4
class StrategicMapOpcodeByteStretch : public stretch<unsigned char> {};

// VTABLE: IMPERIALISM 0x006404a8
class StrategicMapCursorStretch : public stretch<int> {};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

ASSERT_SIZE(StrategicMapOpcodeByteStretch, 0x10);
ASSERT_SIZE(StrategicMapCursorStretch, 0x10);

struct StrategicMapCallbackRecord {
  StrategicMapCallbackRecord();
  ~StrategicMapCallbackRecord();

  void AppendPackedColorDword(unsigned char* destinationPixels, int packedColor);
  void StreamOverlayHitMaskToSurfaceDib(DiplomacyMaskBufferRun* run,
                                        TQuickDrawSurfaceContext* surface, int outlineOnly);
  void BuildDiplomacyOverlayHitMaskOpcodeStream(DiplomacyMaskBufferRun* run,
                                                int destinationRowStride, int outlineOnly,
                                                int surfaceHeight);
  StrategicMapCallbackRecord* AppendOpcodeByte(int value); // returns this (original mov eax,esi)
  void AppendOpcodeBytePair(int value);
  void FinalizeOpcodeBufferAlignment();
  void BuildBitmapMaskOpcodeBufferFromResourceRows(int resourceId, short width, short height,
                                                   int destinationRowStride,
                                                   unsigned char transparentPixel);
  void ApplyBitmapMaskToPixelBuffer(unsigned char* destinationPixels);
  void SetDestinationHeightNoOp(int unusedHeight);

  StrategicMapOpcodeByteStretch opcodeBytes;
  int opcodeAppendCursor;
  // Rolling modulo-four offset used while aligning the generated opcode stream.
  int opcodeAlignmentOffset;
  int hadTrailingPadding;
  StrategicMapCursorStretch packedColorCursor;
  int destinationRowStride;
};

ASSERT_SIZE(StrategicMapCallbackRecord, 0x30);
