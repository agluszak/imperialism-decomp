#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern "C" char* g_pLoungeLocalPlayerNameSharedText_0065c160;
#include "game/net/TWNetSessionManager.h"

#include <afxtempl.h>

extern TWNetSessionManager g_NetworkSessionManager006a5f60;

extern const GUID g_ImperialismDirectPlayApplicationGuid0066f968;

extern CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_RuntimeSelectionRecords006a15e0;

extern CArray<void*, void*> g_WNetSerializedPtrArrayA006a5f10;

extern CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_WNetSerializedPtrArrayB006a5f28;

extern CList<void*, void*> g_WNetPendingPacketList006a5f40;

extern POINT g_ptNetworkModalMessage006a5ed8;

extern POINT g_ptNationAwolModalMessage; // @ 0x6a3d08

extern const char* const g_pszClientSavePrefix_0065BF5C; // "cli_" @ 0x65bf5c

extern char g_szUiOpenParen_0069806C[];

extern "C" {

// The live tactical battle (turn-event 0x29/0x2a receive dispatch target).
extern TTacticalBattle* g_pActiveTacticalBattle;

// OR-accumulator for the turn-event-0x2b presence-mask exchange.
extern int g_nTurnEvent2BNationMaskAccumulator;

// WNetMgr.cpp TU globals (0x6a5fxx band), consumed by TNetMgr::Send / TWNetSessionManager.
// The pending-packet queue and its two serialization siblings are file-scope MFC template
// statics (see the typed C++ section below).
extern int DAT_006a601c;

extern int g_suppressUnexpectedDirectPlaySystemMessageAssert006a6020;

extern "C" const char s_SourcePathUMultiplayerMgr_00698040[];

extern "C" const char s_GameName_00698010[];

extern "C" const char s_PlayerName_0069801c[];

} // extern "C"
