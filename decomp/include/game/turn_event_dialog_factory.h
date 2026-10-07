#pragma once

#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/turn_event_codes.h"

// Turn-event dialog factories: each builds its screen's control tree when the event code is
// its own and returns the tree root, otherwise null.

TView* __cdecl BuildTradeSchoolDialogControls(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeIndustryOverviewPlacardsAndTradeStatusTags(CWnd* pHostWindow,
                                                                    int nEventCode);
TView* __cdecl InitializeIndustryViewTradeMoveControlsAndCommodityRows(CWnd* pHostWindow,
                                                                       int nEventCode);
TView* __cdecl BuildBattleReportOrDiplomacyMapDialogResources(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeDealBookScreenControlsAndCommandTags(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildTurnEventDialogUiByCode(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeArmyNavyReportViewsAndCommandTags(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildTurnEventDialogResources_2508(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeJoinSelectorDialogControlsAndNationSlots(CWnd* pHostWindow,
                                                                  int nEventCode);
TView* __cdecl BuildUiResourceTreeByTemplateIdAndBindScreenContext(CWnd* pHostWindow,
                                                                   int nEventCode);
TView* __cdecl InitializeGameSetupScreenControlsAndModeTags(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeTacticalBattleViewToolbarAndDialogControls(CWnd* pHostWindow,
                                                                    int nEventCode);
TView* __cdecl BuildTechnologyAdvanceDialogResources(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildTechnologyStoreDialogResources(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeTradeScreenBitmapControls(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildTransportDialogResources(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildUniversityDialogShell(CWnd* pHostWindow, int nEventCode);
