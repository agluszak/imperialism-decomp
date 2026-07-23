#pragma once

#include "game/ui_fourcc.h"

// Four-character tags generic widget and view plumbing.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kControlTag1or2 = IMPERIALISM_FOURCC('1', 'o', 'r', '2'); // TViewMgr.cpp; 1 Mac screen(s)
const int kControlTagAMBI =
    IMPERIALISM_FOURCC('A', 'M', 'B', 'I'); // TAmbitFileBasedDocument.cpp, global_data_tables.cpp
const int kControlTagArms = IMPERIALISM_FOURCC('A', 'r', 'm', 's'); // TStatusButton.cpp
const int kControlTagClos = IMPERIALISM_FOURCC('C', 'l', 'o', 's'); // TStatusButton.cpp
const int kControlTagCost =
    IMPERIALISM_FOURCC('C', 'o', 's', 't'); // TMinorTradeBidsDialog.cpp; 3 Mac screen(s)
const int kControlTagDoneCaps =
    IMPERIALISM_FOURCC('D', 'O', 'N', 'E'); // TToolBarCluster.cpp; 1 Mac screen(s)
const int kControlTagFlagCaps =
    IMPERIALISM_FOURCC('F', 'l', 'a', 'g'); // TToolBarCluster.cpp; 1 Mac screen(s)
const int kControlTagHeyBang = IMPERIALISM_FOURCC('H', 'e', 'y', '!'); // TViewMgr.cpp
const int kControlTagIncl = IMPERIALISM_FOURCC('I', 'n', 'c', 'l');    // TViewMgr.cpp
const int kControlTagAbdi =
    IMPERIALISM_FOURCC('a', 'b', 'd', 'i'); // TMultiplayerMgr.cpp, TViewMgr.cpp
const int kControlTagArmyRatioLast =
    IMPERIALISM_FOURCC('a', 'r', 'r', '9'); // Trade screen control tags
const int kControlTagAvai =
    IMPERIALISM_FOURCC('a', 'v', 'a', 'i'); // TAmtBarCluster.cpp; 1 Mac screen(s)
const int kControlTagCard = IMPERIALISM_FOURCC(
    'c', 'a', 'r', 'd'); // TTradeCluster.cpp, TTradeOrderPicture.cpp; 2 Mac screen(s)
const int kControlTagCol1 =
    IMPERIALISM_FOURCC('c', 'o', 'l', '1'); // TMinorTreatyDialog.cpp; 2 Mac screen(s)
const int kControlTagCol2 =
    IMPERIALISM_FOURCC('c', 'o', 'l', '2'); // TMinorTreatyDialog.cpp; 2 Mac screen(s)
const int kControlTagDefe = IMPERIALISM_FOURCC('d', 'e', 'f', 'e'); // TToolBarCluster.cpp
const int kControlTagDipl =
    IMPERIALISM_FOURCC('d', 'i', 'p', 'l'); // TToolBarCluster.cpp, TViewMgr.cpp; 7 Mac screen(s)
const int kControlTagDlog = IMPERIALISM_FOURCC('d', 'l', 'o', 'g'); // TDialogBehavior.cpp
const int kControlTagDono = IMPERIALISM_FOURCC('d', 'o', 'n', 'o'); // TCivToolbar.cpp
const int kControlTagDoof = IMPERIALISM_FOURCC(
    'd', 'o', 'o',
    'f'); // trade-summary food row; the bytes are the reversed spelling doof, distinct from kSummaryTagFood ('food')
const int kControlTagErra = IMPERIALISM_FOURCC('e', 'r', 'r', 'a'); // TTurnStartEvent.h
const int kControlTagForm =
    IMPERIALISM_FOURCC('f', 'o', 'r', 'm'); // TLanguageMgr.cpp; 1 Mac screen(s)
const int kControlTagFrm0 = IMPERIALISM_FOURCC('f', 'r', 'm', '0'); // TLanguageMgr.cpp
const int kControlTagGarr = IMPERIALISM_FOURCC('g', 'a', 'r', 'r'); // Army toolbar control tags
const int kControlTagGd1Sp = IMPERIALISM_FOURCC(
    'g', 'd', '1', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kControlTagGd2Sp = IMPERIALISM_FOURCC(
    'g', 'd', '2', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kControlTagGd3Sp = IMPERIALISM_FOURCC(
    'g', 'd', '3', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kControlTagGree = IMPERIALISM_FOURCC('g', 'r', 'e', 'e'); // Trade summary tags
const int kControlTagHori =
    IMPERIALISM_FOURCC('h', 'o', 'r', 'i'); // TGPTreatyDialog.cpp; 2 Mac screen(s)
const int kControlTagIco1 = IMPERIALISM_FOURCC('i', 'c', 'o', '1'); // primary-resource icon
const int kControlTagIco2 = IMPERIALISM_FOURCC('i', 'c', 'o', '2'); // secondary-resource icon
const int kControlTagIco3 = IMPERIALISM_FOURCC('i', 'c', 'o', '3'); // labor icon
const int kControlTagInst = IMPERIALISM_FOURCC('i', 'n', 's', 't'); // TViewMgr.cpp; 1 Mac screen(s)
const int kControlTagLoss =
    IMPERIALISM_FOURCC('l', 'o', 's', 's'); // TCombatReportView.cpp; 1 Mac screen(s)
const int kControlTagMCap =
    IMPERIALISM_FOURCC('m', 'C', 'a', 'p'); // TTradeCluster.cpp; 3 Mac screen(s)
const int kControlTagMa0Sp = IMPERIALISM_FOURCC(
    'm', 'a', '0', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagMa1Sp = IMPERIALISM_FOURCC(
    'm', 'a', '1', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 3 Mac screen(s)
const int kControlTagMa2Sp = IMPERIALISM_FOURCC(
    'm', 'a', '2', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 3 Mac screen(s)
const int kControlTagMa3Sp = IMPERIALISM_FOURCC(
    'm', 'a', '3', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 3 Mac screen(s)
const int kControlTagMa4Sp = IMPERIALISM_FOURCC(
    'm', 'a', '4', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 3 Mac screen(s)
const int kControlTagMa5Sp = IMPERIALISM_FOURCC(
    'm', 'a', '5', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 3 Mac screen(s)
const int kControlTagMapW = IMPERIALISM_FOURCC(
    'm', 'a', 'p',
    'W'); // map preview window (bytes read mapW, not the 'Wpam' the old comment claimed)
const int kControlTagMovi = IMPERIALISM_FOURCC('m', 'o', 'v', 'i'); // startup movie view
const int kControlTagNam7 =
    IMPERIALISM_FOURCC('n', 'a', 'm', '7'); // TMinorTreatyDialog.cpp; 2 Mac screen(s)
const int kControlTagNumSp =
    IMPERIALISM_FOURCC('n', 'u', 'm', ' '); // TAutomatedPlayDialog.cpp; 1 Mac screen(s)
const int kControlTagOkok = IMPERIALISM_FOURCC('o', 'k', 'o', 'k'); // Civ toolbar control tags
const int kControlTagOpt2 =
    IMPERIALISM_FOURCC('o', 'p', 't', '2'); // TToolBarCluster.cpp; 1 Mac screen(s)
const int kControlTagPgdn =
    IMPERIALISM_FOURCC('p', 'g', 'd', 'n'); // TCombatReportView.cpp; 1 Mac screen(s)
const int kControlTagPgup =
    IMPERIALISM_FOURCC('p', 'g', 'u', 'p'); // TCombatReportView.cpp; 1 Mac screen(s)
const int kControlTagArmyPlacardFirst =
    IMPERIALISM_FOURCC('p', 'i', 'c', '0'); // TArmyToolbar.cpp, TStatusPicture.cpp; 1 Mac screen(s)
const int kControlTagPic1 =
    IMPERIALISM_FOURCC('p', 'i', 'c', '1'); // TWarningView.cpp; 2 Mac screen(s)
const int kControlTagPic5 =
    IMPERIALISM_FOURCC('p', 'i', 'c', '5'); // TViewMgr.cpp, TWarningView.cpp; 2 Mac screen(s)
const int kSummaryTagPopu =
    IMPERIALISM_FOURCC('p', 'o', 'p', 'u'); // TRailAmtBar.cpp, TRailCluster.cpp; 1 Mac screen(s)
const int kControlTagPopv =
    IMPERIALISM_FOURCC('p', 'o', 'p', 'v'); // TRailAmtBar.cpp, TRailCluster.cpp
const int kControlTagProg =
    IMPERIALISM_FOURCC('p', 'r', 'o', 'g'); // TRailAmtBar.cpp, TRailCluster.cpp
const int kControlTagQues =
    IMPERIALISM_FOURCC('q', 'u', 'e', 's'); // TLanguageMgr.cpp; 1 Mac screen(s)
const int kControlTagRege =
    IMPERIALISM_FOURCC('r', 'e', 'g', 'e'); // TMacViewMgr.cpp, TMultiplayerMgr.cpp
const int kControlTagRepo = IMPERIALISM_FOURCC(
    'r', 'e', 'p', 'o'); // TCombatReportView.cpp, TMultiplayerMgr.cpp; 1 Mac screen(s)
const int kControlTagRequ =
    IMPERIALISM_FOURCC('r', 'e', 'q', 'u'); // quit-picture "request" control
const int kControlTagReso = IMPERIALISM_FOURCC('r', 'e', 's', 'o'); // TUnitToolbarCluster.cpp
const int kControlTagRewa = IMPERIALISM_FOURCC('r', 'e', 'w', 'a'); // reward picture
const int kControlTagRow1 =
    IMPERIALISM_FOURCC('r', 'o', 'w', '1'); // TMinorTreatyDialog.cpp; 2 Mac screen(s)
const int kControlTagRow2 =
    IMPERIALISM_FOURCC('r', 'o', 'w', '2'); // TMinorTreatyDialog.cpp; 2 Mac screen(s)
const int kControlTagRs0Sp = IMPERIALISM_FOURCC(
    'r', 's', '0', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagRs1Sp = IMPERIALISM_FOURCC(
    'r', 's', '1', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagRs2Sp = IMPERIALISM_FOURCC(
    'r', 's', '2', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagRs3Sp = IMPERIALISM_FOURCC(
    'r', 's', '3', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagRs4Sp = IMPERIALISM_FOURCC(
    'r', 's', '4', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagRs5Sp = IMPERIALISM_FOURCC(
    'r', 's', '5', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagRs6Sp = IMPERIALISM_FOURCC(
    'r', 's', '6', ' '); // TTraderAmtBar.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kControlTagSale =
    IMPERIALISM_FOURCC('s', 'a', 'l', 'e'); // quit-picture sale-summary text
const int kControlTagShow =
    IMPERIALISM_FOURCC('s', 'h', 'o', 'w'); // quit-picture show-summary button
const int kControlTagSlid = IMPERIALISM_FOURCC('s', 'l', 'i', 'd'); // value slider control
const int kControlTagStackSlotFirst = IMPERIALISM_FOURCC('s', 't', 'k', '0'); // TCivToolbar.cpp
const int kControlTagStackSlotLast = IMPERIALISM_FOURCC('s', 't', 'k', '5');  // TCivToolbar.cpp
const int kControlTagSup1 = IMPERIALISM_FOURCC('s', 'u', 'p', '1'); // primary-resource supply bar
const int kControlTagSup2 = IMPERIALISM_FOURCC('s', 'u', 'p', '2'); // secondary-resource supply bar
const int kControlTagSupl = IMPERIALISM_FOURCC('s', 'u', 'p', 'l'); // labor supply bar
const int kControlTagTab1 =
    IMPERIALISM_FOURCC('t', 'a', 'b', '1'); // TStatusPicture.cpp; 1 Mac screen(s)
const int kControlTagTab2 =
    IMPERIALISM_FOURCC('t', 'a', 'b', '2'); // TStatusPicture.cpp; 1 Mac screen(s)
const int kControlTagTab3 =
    IMPERIALISM_FOURCC('t', 'a', 'b', '3'); // TStatusPicture.cpp; 1 Mac screen(s)
const int kControlTagTab9 =
    IMPERIALISM_FOURCC('t', 'a', 'b', '9'); // TStatusPicture.cpp; 1 Mac screen(s)
const int kControlTagToo3 =
    IMPERIALISM_FOURCC('t', 'o', 'o', '3'); // TToolBarCluster.cpp; 1 Mac screen(s)
const int kControlTagTqui =
    IMPERIALISM_FOURCC('t', 'q', 'u', 'i'); // quit-picture equity control; the bytes are tqui
const int kControlTagTrnW = IMPERIALISM_FOURCC('t', 'r', 'n', 'W'); // turn window (bytes read trnW)
const int kControlTagTsho =
    IMPERIALISM_FOURCC('t', 's', 'h', 'o'); // quit-picture shot control; the bytes are tsho
const int kControlTagTtl1 = IMPERIALISM_FOURCC('t', 't', 'l', '1'); // TViewMgr.cpp; 3 Mac screen(s)
const int kControlTagTurn = IMPERIALISM_FOURCC('t', 'u', 'r', 'n'); // TShipyardCluster.cpp
const int kControlTagTwo2 = IMPERIALISM_FOURCC('t', 'w', 'o', '2'); // TViewMgr.cpp; 1 Mac screen(s)
const int kControlTagTxtAt = IMPERIALISM_FOURCC('t', 'x', 't', '@'); // TViewMgr.cpp
const int kControlTagUse1 = IMPERIALISM_FOURCC('u', 's', 'e', '1');  // primary-resource use bar
const int kControlTagUse2 = IMPERIALISM_FOURCC('u', 's', 'e', '2');  // secondary-resource use bar
const int kControlTagUsel = IMPERIALISM_FOURCC('u', 's', 'e', 'l');  // labor use bar
const int kControlTagVert =
    IMPERIALISM_FOURCC('v', 'e', 'r', 't'); // TGPTreatyDialog.cpp; 2 Mac screen(s)
const int kControlTagWord = IMPERIALISM_FOURCC('w', 'o', 'r', 'd'); // TToolBarCluster.cpp
const int kControlTagFwnd =
    IMPERIALISM_FOURCC('f', 'w', 'n', 'd'); // TFloatWindow.cpp float-window type code
