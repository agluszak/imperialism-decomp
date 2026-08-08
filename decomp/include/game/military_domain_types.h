#pragma once

// TMilitaryUnit's specialization of TUnit::orderType. String group 0x2717
// supplies values 0..26; tactical/minister picture names identify 27..29 as
// the Era 1, Era 2, and Era 3 General variants.
enum MilitaryUnitKind {
  kMilitaryUnitMinutemen = 0,
  kMilitaryUnitSkirmishers = 1,
  kMilitaryUnitRegulars = 2,
  kMilitaryUnitGrenadiers = 3,
  kMilitaryUnitHussars = 4,
  kMilitaryUnitCuirassiers = 5,
  kMilitaryUnitLightArtillery = 6,
  kMilitaryUnitArtillery = 7,
  kMilitaryUnitMilitia = 8,
  kMilitaryUnitSharpshooters = 9,
  kMilitaryUnitRifleInfantry = 10,
  kMilitaryUnitGuards = 11,
  kMilitaryUnitScouts = 12,
  kMilitaryUnitCarbineCavalry = 13,
  kMilitaryUnitFieldArtillery = 14,
  kMilitaryUnitSiegeArtillery = 15,
  kMilitaryUnitConscripts = 16,
  kMilitaryUnitRangers = 17,
  kMilitaryUnitInfantry = 18,
  kMilitaryUnitMachineGunners = 19,
  kMilitaryUnitMechanizedInfantry = 20,
  kMilitaryUnitArmor = 21,
  kMilitaryUnitMobileArtillery = 22,
  kMilitaryUnitRailroadGuns = 23,
  kMilitaryUnitSappers = 24,
  kMilitaryUnitCombatEngineers = 25,
  kMilitaryUnitSaboteurs = 26,
  kMilitaryUnitGeneralEra1 = 27,
  kMilitaryUnitGeneralEra2 = 28,
  kMilitaryUnitGeneralEra3 = 29,
  kMilitaryUnitKindCount = 30
};

typedef short MilitaryUnitKindStorage;

inline MilitaryUnitKind DecodeMilitaryUnitKind(MilitaryUnitKindStorage storedKind) {
  return static_cast<MilitaryUnitKind>(storedKind);
}

inline MilitaryUnitKindStorage EncodeMilitaryUnitKind(MilitaryUnitKind kind) {
  return static_cast<MilitaryUnitKindStorage>(kind);
}

// String group 0x2726 names this lookup domain. The retail table is signed-word
// storage, so keep the representation explicit at table and return boundaries.
enum ArmyUnitCategory {
  kArmyUnitCategoryMilitia = 0,
  kArmyUnitCategoryLightInfantry = 1,
  kArmyUnitCategoryRegularInfantry = 2,
  kArmyUnitCategoryHeavyInfantry = 3,
  kArmyUnitCategoryLightCavalry = 4,
  kArmyUnitCategoryHeavyCavalry = 5,
  kArmyUnitCategoryLightArtillery = 6,
  kArmyUnitCategoryHeavyArtillery = 7,
  kArmyUnitCategoryDemolitionist = 8,
  kArmyUnitCategoryGeneral = 9,
  kArmyUnitCategoryCount = 10
};

typedef short ArmyUnitCategoryStorage;

inline ArmyUnitCategory DecodeArmyUnitCategory(ArmyUnitCategoryStorage storedCategory) {
  return static_cast<ArmyUnitCategory>(storedCategory);
}

inline ArmyUnitCategoryStorage EncodeArmyUnitCategory(ArmyUnitCategory category) {
  return static_cast<ArmyUnitCategoryStorage>(category);
}
