#pragma once

#include "compat.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

// BattleRecord's per-participant UI rows are the same serialized 0x2c records that
// TArmyMgr/TNavyMgr build and finalize. The category tag is detailIdentity28;
// resourceType, stockOrRequired, nameBuffer, and strengthBucket supply the category-specific
// UI values. Keep one physical type instead of an overlapping UI-only payload model.
typedef MapOrderBattleSideChildRecord BattleReportDetailRecord;

// The Mac oracle calls the 0x268-byte TArmyMgr report record BattleRecord. Keep that
// identity shared with the already recovered Windows layout instead of maintaining a
// second partial struct for TBattleUnitsView.
typedef MapContextActionRecord BattleRecord;
