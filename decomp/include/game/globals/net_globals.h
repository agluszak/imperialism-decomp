#pragma once
#include "game/globals/global_types.h"

extern "C" char* g_pLoungeLocalPlayerNameSharedText;
#include "game/net/TWNetSessionManager.h"

#include <afxtempl.h>

extern TWNetSessionManager g_NetworkSessionManager006a5f60;

extern const GUID g_ImperialismDirectPlayApplicationGuid;

extern CArray<RuntimeSelectionRecord*, RuntimeSelectionRecord*> g_RuntimeSelectionRecords;

extern CArray<WNetSelectionRecord*, WNetSelectionRecord*> g_WNetSerializedPtrArrayA;

extern CArray<WNetSelectionRecord*, WNetSelectionRecord*> g_WNetSerializedPtrArrayB;

extern CList<void*, void*> g_WNetPendingPacketList;

extern POINT g_ptNetworkModalMessage;

extern POINT g_ptNationAwolModalMessage; // @ 0x6a3d08

extern const char* const g_pszClientSavePrefix; // "cli_" @ 0x65bf5c

extern char g_szUiOpenParen[];

extern "C" {

// The live tactical battle (turn-event 0x29/0x2a receive dispatch target).
extern TTacticalBattle* g_pActiveTacticalBattle;

// OR-accumulator for the turn-event-0x2b presence-mask exchange.
extern int g_nTurnEvent2BNationMaskAccumulator;

extern int DAT_006a601c;

extern int g_suppressUnexpectedDirectPlaySystemMessageAssert;

extern "C" const char s_SourcePathUMultiplayerMgr[];

extern "C" const char s_GameName[];

extern "C" const char s_PlayerName[];

} // extern "C"
