#pragma once

#include "compat.h"

// Four-byte technology prerequisite record. Most readers use the two technology ids;
// milestone unlock code copies the record as one dword and the military-cost path consumes
// that preserved packed representation.
struct TechPrerequisiteIds {
  short primaryTechId;
  short secondaryTechId;
};

union TechPrerequisitePair {
  TechPrerequisiteIds ids;
  unsigned int packedValue;
};

ASSERT_SIZE(TechPrerequisitePair, 4);
