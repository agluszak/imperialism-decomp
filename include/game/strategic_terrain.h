#pragma once

// Closed strategic-map terrain vocabulary. The numeric order is confirmed by
// TMapDialog::PopulateMapContextInfoPanelStringsByTileSelection (0x0051b1c0), which
// passes the signed byte at TTerrainStateRecord+0x00 directly to string group
// 0x1cb7. The Windows resource crosswalk names entries 0..7 as below.
//
// Do not store StrategicTerrainKind directly in packed map records: a VC5 classic enum
// is int-sized, while the original serialized field is one signed byte and uses -1 as
// its unassigned sentinel.
enum StrategicTerrainKind {
  kStrategicTerrainUnassigned = -1,
  kStrategicTerrainPlains = 0,
  kStrategicTerrainForest = 1,
  kStrategicTerrainHills = 2,
  kStrategicTerrainMountain = 3,
  kStrategicTerrainSwamp = 4,
  kStrategicTerrainWater = 5,
  kStrategicTerrainDesert = 6,
  kStrategicTerrainFarmland = 7,
  kStrategicTerrainCount = 8
};

typedef signed char StrategicTerrainKindStorage;
