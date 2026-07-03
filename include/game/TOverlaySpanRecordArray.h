#pragma once

// A custom MFC-CArray-like growable array of 0x18-byte "overlay span" records, used by the
// UMapper region/route subsystem (e.g. the region-border-link table at g_regionBorderLinks
// 0x006a3900). Grow policy: on a miss it reallocs to double the requested size and, if that
// fails, falls back to exactly the requested size.

struct OverlaySpanRecord {
  char bytes[0x18];
};

struct TOverlaySpanRecordArray {
  void* field00;             // +0x00
  OverlaySpanRecord* buffer; // +0x04
  unsigned int capacity;     // +0x08 (element capacity)
  unsigned int count;        // +0x0c (elements in use)

  void ReserveCapacity(unsigned int newCount);             // 0x0052b3e0
  OverlaySpanRecord* GetOrCreateEntry(unsigned int index); // 0x0052b460
  void* DetachBuffer();                                    // 0x0052b500
  void ReallocBuffer(int newCount);                        // 0x0052e310
};
