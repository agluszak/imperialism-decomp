#pragma once
#include "game/globals/global_types.h"

extern "C" short g_aTradeDealCategoryOrder[17];

extern POINT g_ptControlStringModalMessage;

extern const short g_tradeBookCategoryByTabAndTechState[2][17];

extern TTradeMgr* g_pTradeMgr;
extern const char* g_cstrTradeTotalsBalanceSubstitution;

// Offer-desk Locate positions initialized by the retail startup table.
extern "C" CPoint g_offerDeskSheetPosition;
extern "C" CPoint g_offerDeskOffscreenPosition;

extern "C" const int g_pTradeSummarySelectionMap[23];

extern "C" const char s_SourcePathUTradeViews[];
