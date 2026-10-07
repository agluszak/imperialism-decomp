#pragma once
#include "game/globals/global_types.h"

extern POINT g_ptDiplomacyNoticeModalMessage;
extern "C" unsigned int g_aDiplomacyActionTopicTabTags[6];

extern short g_awDiplomacyGrantValueTable[4];
extern short g_awDiplomacyTradePolicyIconValueTable[7];

extern CPoint g_diplomacyPopupVisiblePosition;

extern CPoint g_diplomacyPopupOffscreenPosition;

extern "C" {
extern char* g_pDiplomacyPanelEmptyText;

extern "C" int g_diplomacyActionButtonTagTable[6];

extern "C" short g_aDiplomacyRelationPaletteColorCodes[7];

extern "C" char s_SourcePathUDiplomacyViews[];

} // extern "C"
