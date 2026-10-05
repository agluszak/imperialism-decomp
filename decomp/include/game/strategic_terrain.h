#pragma once

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
