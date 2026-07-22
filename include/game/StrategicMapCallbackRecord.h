#pragma once

#include "compat.h"
#include "game/mfc.h"

struct StrategicMapCallbackRecord {
  StrategicMapCallbackRecord();
  ~StrategicMapCallbackRecord();

  void AppendPackedColorDword(int surface, int packedColor);
  unsigned char* EnsureOpcodeBufferByteAtIndex(int index);
  StrategicMapCallbackRecord* AppendOpcodeByte(int value); // returns this (original mov eax,esi)
  void AppendOpcodeBytePair(int value);
  void FinalizeOpcodeBufferAlignment();
  void BuildBitmapMaskOpcodeBufferFromResourceRows(int resourceId, short width, short height,
                                                   int destinationRowStride,
                                                   unsigned char transparentPixel);
  // Apply the generated sparse bitmap writes to a destination tile. The retail build executes
  // the generated x86 stream directly; interpreting the same opcodes keeps the recovered source
  // portable and avoids inline assembly while preserving the mask semantics.
  void ApplyBitmapMaskToPixelBuffer(unsigned char* destinationPixels);

  // dispatchTable00/subobjectDispatchTable1c (below) are NOT a C++ vfptr despite the ctor
  // writing a shared constant .rdata address into both, matching each dtor-restore before the
  // owned buffer is freed: `just xrefs to 0x006404a4/0x006404a8` shows zero read/call sites
  // anywhere in the binary -- only these two ctor/dtor writes -- so nothing ever dispatches
  // through them. The two addresses are adjacent slots in one shared 2-entry .rdata table;
  // each dword there is an ILT-thunk to a distinct compiler-emitted
  // WrapperFor_ReallocateHeapBlockWithAllocatorTracking_At... COMDAT (0x004307a0 for slot 0,
  // 0x00430830 for slot 1 -- both tail-calling CRT _realloc, see
  // config/original_entities.csv:153-154 and the LIBRARY note in mfc_heap_library.cpp:7-9), one
  // per owned buffer (ownedBuffer04 / ownedBuffer20). A QuickDraw-style per-buffer "procs table"
  // reference carried over from the Mac codebase, not compiler vtable dispatch.
  int dispatchTable00;
  char* ownedBuffer04;
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
  char* ownedBuffer20;
  // cursorBufferSize24/cursorBufferInitialized28: AppendPackedColorDword (0x004d4bf0) lazily
  // allocates ownedBuffer20 as a single int-sized write-cursor cell the first time
  // cursorBufferSize24 is 0, then sets cursorBufferInitialized28 as a parallel init guard.
  int cursorBufferSize24;
  int cursorBufferInitialized28;
  // destinationRowStride2c: byte stride used when converting each resource pixel's (x,y)
  // coordinate into its destination-tile offset. No read site outside mask construction.
  int destinationRowStride2c;
};

ASSERT_SIZE(StrategicMapCallbackRecord, 0x30);
