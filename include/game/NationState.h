#pragma once

// Model B (2026-06-09): no shared polymorphic NationState base — great powers are
// TGreatPower / TAutoGreatPower; terrain/minor rows are TSecondaryNationState.
// This header keeps trade/diplomacy includes stable while the shim retires.

#include "game/TGreatPower.h"
#include "game/TSecondaryNationState.h"

struct NationCityTradeState; // trade-screen layout in trade_quickdraw.h
