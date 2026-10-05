#pragma once

#include "compat.h"

#include "game/diplomacy_domain_types.h"

typedef short NationSlot;
enum eMissionDesirability {
  kMissionDesirabilityUnmarked = 0,
  kMissionDesirabilityCandidate = 1,
  kMissionDesirabilityQueued = 2
};
enum { kMajorNationCount = 7, kNationSlotCount = 23, kMinorNationFirstSlot = kMajorNationCount };
typedef short EncodedNationSlot;
typedef short GrantEntry;
typedef short NeedType;
typedef short RelationDelta;

struct CongressLeadership {
  NationSlot chairmanNationSlot;    // top-ranked nation by comparative standing
  NationSlot counterpartNationSlot; // runner-up nation
};
ASSERT_SIZE(CongressLeadership, 4);

struct CongressSupportTally {
  short chairmanSupportCount;    // provinces backing chairmanNationSlot
  short counterpartSupportCount; // provinces backing counterpartNationSlot
  short neutralCount;            // owned provinces backing neither side
};
ASSERT_SIZE(CongressSupportTally, 6);
