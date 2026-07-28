#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern POINT g_ptControlStringModalMessage;

extern short g_offerDeskSelectionIndexTable_00668568[8];

extern TTradeMgr* g_pTradeMgr;
extern const char* g_cstrTradeTotalsBalanceSubstitution0066DB50;

// Offer-desk Locate positions initialized by the retail startup table.
extern "C" CPoint g_offerDeskSheetPosition_006a5a00;
extern "C" CPoint g_offerDeskOffscreenPosition_006a5a28;

extern "C" const int g_pTradeSummarySelectionMap[23];
