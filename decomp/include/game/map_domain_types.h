#pragma once

typedef short StrategicTileIndex;

typedef int TacticalTileIndex;

typedef int ProvinceIndex;
typedef short ProvinceIndexStorage;

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

enum TacticalHexDirection {
  kTacticalHexDirectionNorthEast = 0,
  kTacticalHexDirectionEast = 1,
  kTacticalHexDirectionSouthEast = 2,
  kTacticalHexDirectionSouthWest = 3,
  kTacticalHexDirectionWest = 4,
  kTacticalHexDirectionNorthWest = 5,
  kTacticalHexDirectionCount = 6
};

enum MapScrollEdgeFlag {
  kMapScrollEdgeBottom = 0x01,
  kMapScrollEdgeTop = 0x02,
  kMapScrollEdgeRight = 0x04,
  kMapScrollEdgeLeft = 0x08
};

typedef short MapScrollEdgeMaskStorage;
typedef unsigned char MapScrollEdgeMaskByteStorage;

typedef unsigned char RiverSpriteCodeStorage;

enum RiverSpriteCode {
  kRiverSpriteCodeNone = 0,
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
