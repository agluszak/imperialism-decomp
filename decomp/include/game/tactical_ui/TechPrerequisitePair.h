#pragma once

#include "compat.h"

// Four-byte technology prerequisite record.
struct TechPrerequisitePair {
  short primaryTechId;
  short secondaryTechId;
};

ASSERT_SIZE(TechPrerequisitePair, 4);
