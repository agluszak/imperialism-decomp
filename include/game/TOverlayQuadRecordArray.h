#pragma once

// A custom MFC-CArray-like growable array of 0x10-byte "overlay quad" records, used by the
// UMapper overlay subsystem. Same grow policy as TOverlaySpanRecordArray (double-or-fallback),
// but with a 0x10-byte element stride.

struct OverlayQuadRecord {
  char bytes[0x10];
};

struct TOverlayQuadRecordArray {
  void* field00;             // +0x00
  OverlayQuadRecord* buffer; // +0x04
  unsigned int capacity;     // +0x08 (element capacity)
  unsigned int count;        // +0x0c (elements in use)

  void ReserveCapacity(unsigned int newCount);             // 0x0052d0d0
  OverlayQuadRecord* GetOrCreateEntry(unsigned int index); // 0x0052d150
};
