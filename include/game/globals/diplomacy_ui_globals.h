#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

extern POINT g_ptDiplomacyNoticeModalMessage;              // @ 0x6a2fc0
extern "C" unsigned int g_aDiplomacyActionTopicTabTags[6]; // @ 0x696978

extern short g_awDiplomacyGrantValueTable[4];
extern short g_awDiplomacyTradePolicyIconValueTable[7];

// Persistent (X,Y) layout-capture buffer shared by the diplomacy popup family
// (TOffersPanelView::PoseOffer, TOffersPanelView::PoseWarOffer,
// InitializeDiplomacyMinisterActionControlsAndLabels) via TView::Locate, which
// reads exactly buffer[0]/buffer[1] as ownerLocalX/ownerLocalY.
extern CPoint g_diplomacyWarOfferSheetPosition_006a2fe0;

extern CPoint g_diplomacyPopupLayoutPosition_006a3020;

extern "C" {
extern char* g_pDiplomacyPanelEmptyText_00654ec8;

extern "C" int g_diplomacyActionButtonTagTable_00696960[6];

extern "C" short g_aDiplomacyRelationPaletteColorCodes[7];

extern "C" const char s_SourcePathUDiplomacyViews_00696AE0[];

} // extern "C"
