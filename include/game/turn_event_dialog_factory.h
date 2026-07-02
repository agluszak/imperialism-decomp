#pragma once

#include "game/TView.h"
#include "game/mfc.h"

// Turn-event dialog factory callbacks registered by RegisterStartupDialogFactoryCallbacks
// (see TTurnEventDialogFactoryRegistry). Each is invoked as factory(0, nEventCode) from
// RunRegisteredDialogFactoriesByEventCode; a factory checks the event code, builds its
// screen's control tree on the global widget build stack, and returns the tree root
// (g_pUiResourceHead) or null when the code is not its own. pHostWindow is propagated
// into the built tree via TView::PropagateUiResourceContextRecursive.

TView* __cdecl BuildTradeSchoolDialogControls(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeIndustryOverviewPlacardsAndTradeStatusTags(CWnd* pHostWindow,
                                                                    int nEventCode);
TView* __cdecl InitializeIndustryViewTradeMoveControlsAndCommodityRows(CWnd* pHostWindow,
                                                                       int nEventCode);
TView* __cdecl BuildTurnEventDialogResourcesForEvent547Or7D8(CWnd* pHostWindow, int nEventCode);
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
TView* __cdecl BuildTurnEventDialogResourcesForEvent898(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildTurnEventDialogResourcesForEvent8FC(CWnd* pHostWindow, int nEventCode);
TView* __cdecl InitializeTradeScreenBitmapControls(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildTurnEventDialogResourcesForEvent7DE(CWnd* pHostWindow, int nEventCode);
TView* __cdecl BuildUniversityDialogShell(CWnd* pHostWindow, int nEventCode);
