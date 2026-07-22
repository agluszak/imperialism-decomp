#pragma once

// Mac CodeWarrior names this UI/action discriminator eDipAction. The values are
// int-sized at method boundaries and index the 16-entry diplomacy cursor table.
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

// Proposal records and turn-event-0x16 packets store this discriminator in a
// signed 16-bit field. Keep that storage/ABI type distinct from the semantic
// constants so the original word loads and serialized layout remain explicit.
typedef short DiplomacyProposalCodeStorage;

enum DiplomacyProposalKind {
  kDiplomacyProposalJoinEmpire = 0x12D,
  kDiplomacyProposalAlliance = 0x12E,
  kDiplomacyProposalNonAggressionPact = 0x12F,
  kDiplomacyProposalPeaceTreaty = 0x130,
  kDiplomacyProposalDeclareWar = 0x131,
  kDiplomacyProposalJoinEmpireWithWarEntanglements = 0x132
};

// The relation matrix and getter use signed 16-bit storage. Setters receive an
// int-sized enum value and narrow it once when writing the matrix.
typedef short DiplomacyRelationshipStorage;

enum DiplomacyRelationship {
  kDiplomacyRelationshipAlliance = 2,
  kDiplomacyRelationshipNonAggressionPact = 3,
  kDiplomacyRelationshipPeace = 4,
  kDiplomacyRelationshipJoinedEmpire = 5,
  kDiplomacyRelationshipWar = 6
};
