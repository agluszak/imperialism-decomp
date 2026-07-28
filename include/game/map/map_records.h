#pragma once

#include "compat.h"

class TCivUnit;

struct GlobalMapTileRecord {
  char pad_00_to_1f[0x20];
  TCivUnit* firstCivilianOrder; // 0x20
};

// Raw 0x24-byte tile record as stored in a Mac-endian scenario file. It remains separate
// from the runtime tile view because its word fields are swapped only at the load boundary.
struct ScenarioTileDiskRecord {
  unsigned char bytes00[4];
  signed char ownerNationTag04;
  unsigned char bytes05[0x14 - 0x05];
  unsigned char cityRecordIndex14[2];
  unsigned char bytes16[0x1a - 0x16];
  unsigned char tileActionOrdinal1a[2];
  unsigned char activeFlags1c[2];
  unsigned char bytes1e[2];
  int transientPointerBits20;
};
ASSERT_SIZE(ScenarioTileDiskRecord, 0x24);

// Packed 108x60 source tile pairs used by TMapMgr::ReadInRGBMap.
struct MapPixelSourceView {
  int unknown00;
  int unknown04;
  const short* packedTiles; // +0x08
};
