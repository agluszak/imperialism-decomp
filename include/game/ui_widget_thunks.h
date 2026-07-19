#pragma once

// Shared free-function thunk declarations for the widget / trade-screen
// ecosystem. These are the ABI bridges and lifecycle hooks that the widget
// class files and TradeScreenRuntimeBridge route through. Extracted from
// ui_widget_shared.h.

#include "decomp_types.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

undefined4 ActivateFirstIdleTacticalUnitByCategoryAtTile(void);
undefined4 ActivateFirstActiveTacticalUnitByCategoryAtTile(void);
