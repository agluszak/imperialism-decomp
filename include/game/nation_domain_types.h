#pragma once

#include "game/diplomacy_domain_types.h"

typedef short NationSlot;
// Serialized terrain/nation ownership tag. -1 means unassigned; 0..22 is a direct
// NationSlot, 100..122 and 200..222 are ownership-mode encodings. Decode before using
// it as an array index or passing it to a NationSlot API.
typedef short EncodedNationSlot;
typedef short GrantEntry;
typedef short NeedType;
typedef short RelationDelta;
