#pragma once

// TCivUnit's specialization of TUnit::orderType. The Windows and Mac resource
// string group 0x2718 indexes these nine civilian unit kinds in this order.
// TUnit::orderType itself remains a serialized short because other TUnit
// subclasses reuse that base slot for distinct military and naval domains.
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

// Result of TCivMgr::GetTileAction/ResolveCivilianTileOrderActionCode. The producer
// and HandleCivilianTileOrderAction cover the complete 0..11 dispatch table.
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
