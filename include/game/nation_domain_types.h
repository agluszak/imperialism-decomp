#pragma once

#include "compat.h"

#include "game/diplomacy_domain_types.h"

typedef short NationSlot;
// Serialized terrain/nation ownership tag. -1 means unassigned; 0..22 is a direct
// NationSlot, 100..122 and 200..222 are ownership-mode encodings. Decode before using
// it as an array index or passing it to a NationSlot API.
typedef short EncodedNationSlot;
typedef short GrantEntry;
typedef short NeedType;
typedef short RelationDelta;

// The two great powers a diplomatic congress is convened around. Written together by
// TDiplomacyMgr::RebuildDiplomacyStandingAndInfluenceMatrices (0x4f0e20), which fills
// them straight from BuildMajorNationDiplomacyStandingRanking's top/runner-up outputs,
// and read back as a pair by TCouncilPanelView::Draw (0x4fb030) -- a chairman slot of
// -1 there means "no summit in session". The turn-event-0x26 wire snapshot carries the
// same record, which is why both sides copy it as one four-byte unit.
struct CongressLeadership {
  NationSlot chairmanNationSlot;    // top-ranked nation by comparative standing
  NationSlot counterpartNationSlot; // runner-up nation
};
ASSERT_SIZE(CongressLeadership, 4);

// How the owned provinces split across the congress. Recomputed in one place, at the
// tail of TDiplomacyMgr::RebuildDiplomacyStandingAndInfluenceMatrices (0x4f0e20), from
// that function's topSideCount / secondSideCount / (totalOwnedCount - the other two)
// running totals; TCouncilPanelView::Draw (0x4fb030) prints them as the three
// "<nation>: <count>" rows of the council header, in this order.
struct CongressSupportTally {
  short chairmanSupportCount;    // provinces backing chairmanNationSlot
  short counterpartSupportCount; // provinces backing counterpartNationSlot
  short neutralCount;            // owned provinces backing neither side
};
ASSERT_SIZE(CongressSupportTally, 6);
