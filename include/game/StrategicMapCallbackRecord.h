#pragma once

#include "compat.h"
#include "game/mfc.h"

struct StrategicMapCallbackRecord {
  StrategicMapCallbackRecord();
  ~StrategicMapCallbackRecord();

  void AppendPackedColorDword(unsigned char* destinationPixels, int packedColor);
  unsigned char* EnsureOpcodeBufferByteAtIndex(int index);
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

  // The two one-entry tables dispatch element-sized append/grow operations for the byte and int
  // buffers. They are called at 0x004d53f2 and 0x004d5d94 and target the type-specific routines
  // at 0x004307a0/0x00430830. Their exact source container type remains unrecovered.
  int dispatchTable00;
  unsigned char* ownedBuffer04;
  // bufferCapacity08/committedLength0c: EnsureOpcodeBufferByteAtIndex and AppendOpcodeByte
  // both compare against bufferCapacity08 before growing ownedBuffer04 via realloc/new, and
  // raise committedLength0c to index+1 whenever a touched index exceeds it (also used as the
  // memcpy length when the buffer grows) -- see 0x004d4e40, 0x004d5580.
  union {
    struct {
      int bufferCapacity08;
      int committedLength0c;
      // appendCursor10: AppendOpcodeByte's own private monotonically-incrementing write cursor
      // (0x004d5580); distinct from committedLength0c, which EnsureOpcodeBufferByteAtIndex also
      // advances via direct indexed writes.
      int appendCursor10;
      // alignmentCursor14: FinalizeOpcodeBufferAlignment's rolling mod-4 pad counter (0x004d5720);
      // AppendPackedColorDword (0x004d4bf0) also reads it as the JIT entry-point offset into
      // ownedBuffer04, since that call path never invokes FinalizeOpcodeBufferAlignment.
      int alignmentCursor14;
    };
    // BuildDiplomacyNationOverlayGeometryAndHitMasks temporarily uses this four-dword
    // bookkeeping region as rectangle scratch before emitting any opcodes.
    RECT scratchBounds08;
  };
  // hadTrailingPadding18: set to 1 by FinalizeOpcodeBufferAlignment when alignmentCursor14 is
  // still nonzero at exit (0x004d5720).
  int hadTrailingPadding18;
  int subobjectDispatchTable1c;
  int* ownedBuffer20;
  // cursorBufferSize24/cursorBufferInitialized28: AppendPackedColorDword (0x004d4bf0) lazily
  // allocates ownedBuffer20 as a single write-cursor element the first time
  // cursorBufferSize24 is 0, then sets cursorBufferInitialized28 as a parallel init guard.
  int cursorBufferSize24;
  int cursorBufferInitialized28;
  // destinationRowStride2c: byte stride used when converting each resource pixel's (x,y)
  // coordinate into its destination-tile offset. No read site outside mask construction.
  int destinationRowStride2c;
};

ASSERT_SIZE(StrategicMapCallbackRecord, 0x30);
