#pragma once

enum CivilianUnitKind {
  kCivilianUnitMiner = 0,
  kCivilianUnitProspector = 1,
  kCivilianUnitFarmer = 2,
  kCivilianUnitForester = 3,
  kCivilianUnitEngineer = 4,
  kCivilianUnitRancher = 5,
  kCivilianUnitFisherman = 6,
  kCivilianUnitDeveloper = 7,
  kCivilianUnitDriller = 8,
  kCivilianUnitKindCount = 9
};

typedef short CivilianUnitKindStorage;

inline CivilianUnitKind DecodeCivilianUnitKind(CivilianUnitKindStorage storedKind) {
  return static_cast<CivilianUnitKind>(storedKind);
}

inline CivilianUnitKindStorage EncodeCivilianUnitKind(CivilianUnitKind kind) {
  return static_cast<CivilianUnitKindStorage>(kind);
}

enum CivilianTileActionCode {
  kCivilianTileActionNone = 0,
  kCivilianTileActionBlocked = 1,
  kCivilianTileActionSelectUnit = 2,
  kCivilianTileActionMoveUnit = 3,
  kCivilianTileActionEngineerSameTile = 4,
  kCivilianTileActionEngineerDirection14 = 5,
  kCivilianTileActionEngineerDirection03 = 6,
  kCivilianTileActionEngineerDirection25 = 7,
  kCivilianTileActionProspect = 8,
  kCivilianTileActionDevelopResource = 9,
  kCivilianTileActionShowOrderReport = 10,
  kCivilianTileActionPurchaseLand = 11
};
typedef int CivilianTileActionCodeStorage;
