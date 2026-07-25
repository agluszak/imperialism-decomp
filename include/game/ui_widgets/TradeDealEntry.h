#pragma once

#include "compat.h"

// 0x10-byte payload copied into TDealList's fixed-record storage. The producer at
// 0x005b8080 writes the four word fields, the full dispatch score returned in EAX,
// and the category word before InsertCopiedRecordSortedByComparator copies all 16 bytes.
struct TradeDealEntry {
  short sourceNationSlot;   // +0x00
  short targetNationSlot;   // +0x02
  short relationDelta04;    // +0x04
  short relationStanding06; // +0x06
  int dispatchScore08;      // +0x08
  short category0c;         // +0x0c
};
ASSERT_SIZE(TradeDealEntry, 0x10);
