#pragma once
#include "game/globals/global_types.h"

extern POINT g_ptDiplomacyNoticeModalMessage;              // @ 0x6a2fc0
extern "C" unsigned int g_aDiplomacyActionTopicTabTags[6]; // @ 0x696978

extern short g_awDiplomacyGrantValueTable[4];
extern short g_awDiplomacyTradePolicyIconValueTable[7];

extern CPoint g_diplomacyPopupVisiblePosition_006a2fe0;

extern CPoint g_diplomacyPopupOffscreenPosition_006a3020;

extern "C" {
extern char* g_pDiplomacyPanelEmptyText_00654ec8;

extern "C" int g_diplomacyActionButtonTagTable_00696960[6];

extern "C" short g_aDiplomacyRelationPaletteColorCodes[7];

extern "C" const char s_SourcePathUDiplomacyViews_00696AE0[];

} // extern "C"
