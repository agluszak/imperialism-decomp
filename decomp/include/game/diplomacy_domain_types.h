#pragma once

// Trade policy toward a nation: a price percentage, 100 normal, below 100 a subsidy.
enum { kTradePolicyNormal = 100, kTradePolicyBoycott = 300 };

enum eDipAction {
  kDipActionNone = 0,
  kDipActionSelectedNation = 1,
  kDipActionJoinEmpire = 2,
  kDipActionAlliance = 3,
  kDipActionNonAggressionPact = 4,
  kDipActionPeaceTreaty = 5,
  kDipActionDeclareWar = 6,
  kDipActionOneTimeGrant = 7,
  kDipActionRecurringGrant = 8,
  kDipActionTradeSubsidy = 9,
  kDipActionTradePolicy = 10,
  kDipActionBoycott = 11,
  kDipActionLinkTradePolicy = 12,
  kDipActionInspectNation = 13,
  kDipActionBuildConsulate = 14,
  kDipActionBuildEmbassy = 15
};

typedef short DiplomacyProposalCodeStorage;

enum DiplomacyProposalKind {
  kDiplomacyProposalJoinEmpire = 0x12D,
  kDiplomacyProposalAlliance = 0x12E,
  kDiplomacyProposalNonAggressionPact = 0x12F,
  kDiplomacyProposalPeaceTreaty = 0x130,
  kDiplomacyProposalDeclareWar = 0x131,
  kDiplomacyProposalJoinEmpireWithWarEntanglements = 0x132,
  kDiplomacyProposalBuildConsulate = 0x133,
  kDiplomacyProposalBuildEmbassy = 0x134
};

// The relation matrix and diplomacy-manager setter ABI use signed 16-bit storage.
typedef short DiplomacyRelationshipStorage;

enum DiplomacyRelationship {
  kDiplomacyRelationshipAlliance = 2,
  kDiplomacyRelationshipNonAggressionPact = 3,
  kDiplomacyRelationshipPeace = 4,
  kDiplomacyRelationshipJoinedEmpire = 5,
  kDiplomacyRelationshipWar = 6
};

enum DiplomacyRelationshipNotch {
  kDiplomacyRelationshipNotchThrough20 = 0,
  kDiplomacyRelationshipNotchThrough49 = 1,
  kDiplomacyRelationshipNotchThrough79 = 2,
  kDiplomacyRelationshipNotchThrough100 = 3,
  kDiplomacyRelationshipNotchThrough135 = 4,
  kDiplomacyRelationshipNotchThrough170 = 5,
  kDiplomacyRelationshipNotchThrough205 = 6,
  kDiplomacyRelationshipNotchThrough240 = 7,
  kDiplomacyRelationshipNotchAbove240 = 8
};

typedef short DiplomaticMissionLevelStorage;

enum DiplomaticMissionLevel {
  kDiplomaticMissionNone = 0,
  kDiplomaticMissionTradeConsulate = 1,
  kDiplomaticMissionEmbassy = 2
};

struct RelationshipRankEntry {
  short nationSlot;
  short standingScore;
};
