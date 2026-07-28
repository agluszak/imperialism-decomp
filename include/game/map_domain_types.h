#pragma once

// Strategic-map tile identity is stored and passed as a signed 16-bit value at the
// game-owned map boundary. The 108x60 map occupies 0..6479 and uses -1 as the common
// invalid/not-found sentinel. Representative listings 0x005125a0, 0x00512cc0, and
// 0x005136a0 load the argument as a word and sign-extend it before arithmetic/indexing.
typedef short StrategicTileIndex;

// Tactical battles use a separate 15x29 grid domain. Its indices, neighbor arrays,
// path buffers, and unit fields are all full dwords; 0x005a0420 reads and writes
// dwords throughout and 0x005a0550 compares a six-element dword neighbor array.
typedef int TacticalTileIndex;

// Province/city-score identity is a full int in table arithmetic and most game-owned
// APIs (0x0050e2c0 computes it from a pointer difference; 0x0050fca0 consumes a dword).
// Packed terrain/Province records and a few legacy stack boundaries retain signed
// 16-bit storage (0x005149d0 sign-extends its word argument).
typedef int ProvinceIndex;
typedef short ProvinceIndexStorage;

// Strategic-map hex directions follow the retail neighbor-array ordering. The
// word storage type is retained at the Windows/Mac map APIs that load or return
// only AX; full-width loop variables can use StrategicHexDirection directly.
enum StrategicHexDirection {
  kStrategicHexDirectionNorthEast = 0,
  kStrategicHexDirectionEast = 1,
  kStrategicHexDirectionSouthEast = 2,
  kStrategicHexDirectionSouthWest = 3,
  kStrategicHexDirectionWest = 4,
  kStrategicHexDirectionNorthWest = 5,
  kStrategicHexDirectionCount = 6
};

typedef short StrategicHexDirectionStorage;

inline StrategicHexDirection
DecodeStrategicHexDirection(StrategicHexDirectionStorage storedDirection) {
  return static_cast<StrategicHexDirection>(storedDirection);
}

inline StrategicHexDirectionStorage EncodeStrategicHexDirection(StrategicHexDirection direction) {
  return static_cast<StrategicHexDirectionStorage>(direction);
}

// Tactical battles use the same clockwise six-neighbor ordering, but their tile
// and direction APIs are independent full-dword boundaries (0x005a0420 and
// 0x005a1400). Keep this domain distinct from StrategicHexDirection rather than
// making the matching ordinal representation imply interchangeable APIs.
enum TacticalHexDirection {
  kTacticalHexDirectionNorthEast = 0,
  kTacticalHexDirectionEast = 1,
  kTacticalHexDirectionSouthEast = 2,
  kTacticalHexDirectionSouthWest = 3,
  kTacticalHexDirectionWest = 4,
  kTacticalHexDirectionNorthWest = 5,
  kTacticalHexDirectionCount = 6
};

// The viewport-scroll argument is a four-bit edge mask, not an ordinal
// direction. Mac names the virtual family Scroll(short); Windows listings also
// consume a word while internal map-dialog helpers sometimes narrow to a byte.
enum MapScrollEdgeFlag {
  kMapScrollEdgeBottom = 0x01,
  kMapScrollEdgeTop = 0x02,
  kMapScrollEdgeRight = 0x04,
  kMapScrollEdgeLeft = 0x08
};

typedef short MapScrollEdgeMaskStorage;
typedef unsigned char MapScrollEdgeMaskByteStorage;

// TTerrainStateRecord's river/coast byte is a staged sprite code. 0x80
// marks an unresolved connection shape during map preparation; 0x2b..0x32 and
// 0x33..0x3a are the resolved one-direction land and water sprite families.
// Keep byte storage because the scenario record is packed and serialized.
typedef unsigned char RiverSpriteCodeStorage;

enum RiverSpriteCode {
  kRiverSpriteCodeNone = 0,
  // Multi-direction flow families. TraceTerrainFlowToNearestSeaTile (0x00563990)
  // folds the second family onto the first by subtracting the bias, then resolves the
  // first family through the flow remap table; the single-direction families below
  // carry no traceable flow and end the trace.
  kRiverSpriteCodeFlowFirst = 0x0b,
  kRiverSpriteCodeFlowLast = 0x1a,
  kRiverSpriteCodeFlowVariantFirst = 0x1b,
  kRiverSpriteCodeFlowVariantLast = 0x2a,
  kRiverSpriteCodeFlowVariantBias = 0x10,
  kRiverSpriteCodeLandSingleDirectionFirst = 0x2b,
  kRiverSpriteCodeLandSingleDirectionLast = 0x32,
  kRiverSpriteCodeWaterSingleDirectionFirst = 0x33,
  kRiverSpriteCodeWaterSingleDirectionLast = 0x3a,
  kRiverSpriteCodeNeedsResolution = 0x80
};

// Signed per-tile map marker state. Positive values are active/actionable;
// TZone uses the matching negative magnitude for dimmed marker geometry.
// String group 0x2755 identifies the singleton fleet states below, while the
// two encoded ranges carry a nation/order ordinal or linked-zone marker kind.
typedef signed char MapTileActionStateStorage;

enum MapTileActionState {
  kMapTileActionStateNone = -1,
  kMapTileActionStateBlockadingFleet = 2,
  kMapTileActionStateAnchor = 3,
  kMapTileActionStateMovingFleet = 4,
  kMapTileActionStatePatrollingFleet = 5,
  kMapTileActionStateInvadingFleet = 6,
  kMapTileActionStateNationOrderFirst = 7,
  kMapTileActionStateNationOrderLast = 13,
  kMapTileActionStateDockedFleet = 14,
  kMapTileActionStateLinkedZoneFirst = 14,
  kMapTileActionStateLinkedZoneLast = 21,
  kMapTileActionStatePortZoneMarkerFrame = 14,
  kMapTileActionStateZoneCenterMarkerFrame = 16,
  kMapTileActionStateZoneNorthWestMarkerFrame = 18,
  kMapTileActionStateZoneNorthEastMarkerFrame = 20,
  kMapTileActionStateFleetFrameFirst = 16,
  kMapTileActionStateFleetFrameLast = 17,
  kMapTileActionStateStrategicAtlasFrameCount = 18,
  kMapTileActionStateOceanAtlasFrameCount = 19
};
