#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern POINT g_ptDiplomacyNoticeModalMessage;              // @ 0x6a2fc0
extern "C" unsigned int g_aDiplomacyActionTopicTabTags[6]; // @ 0x696978

extern short g_awDiplomacyGrantValueTable[4];
extern short g_awDiplomacyTradePolicyIconValueTable[7];

// The two constant slots the diplomacy popup family (TOffersPanelView::PoseOffer,
// TOffersPanelView::PoseWarOffer, InitializeDiplomacyMinisterActionControlsAndLabels)
// swaps its children between via TView::Locate, which copies x/y straight into
// ownerLocalX/ownerLocalY. Nothing writes them at runtime: (8, 7) is the in-panel
// position and (2000, 2000) parks a control off-screen in place of a visibility flag.
extern CPoint g_diplomacyPopupVisiblePosition_006a2fe0;

extern CPoint g_diplomacyPopupOffscreenPosition_006a3020;

extern "C" {
extern char* g_pDiplomacyPanelEmptyText_00654ec8;

extern "C" int g_diplomacyActionButtonTagTable_00696960[6];

extern "C" short g_aDiplomacyRelationPaletteColorCodes[7];

extern "C" const char s_SourcePathUDiplomacyViews_00696AE0[];

} // extern "C"
