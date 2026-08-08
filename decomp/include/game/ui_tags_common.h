#pragma once

#include "game/ui_fourcc.h"

// Four-character tags shared across subsystems.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kControlTagSpSpSpSp = IMPERIALISM_FOURCC(
    ' ', ' ', ' ', ' '); // TBehavior.cpp, TBoycottButton.cpp, TCluster.cpp...; 19 Mac screen(s)
const int kControlTagDialog =
    IMPERIALISM_FOURCC('D', 'L', 'O', 'G'); // the root content view inside many dialog windows
const int kControlTagDOOG = IMPERIALISM_FOURCC(
    'D', 'O', 'O', 'G'); // TMapUberPicture.cpp, TNavyToolbarCluster.cpp; 1 Mac screen(s)
const int kControlTagMoil = IMPERIALISM_FOURCC(
    'M', 'o', 'i', 'l'); // TArmoryView.cpp, TLoungeDialog.cpp, TShipyardView.cpp...
const int kControlTagRestartCaps =
    IMPERIALISM_FOURCC('R', 'e', 'S', 't'); // TCouncilView.cpp, TToolBarCluster.cpp
const int kControlTagScoreCaps =
    IMPERIALISM_FOURCC('S', 'c', 'o', 'r'); // TCouncilView.cpp, TToolBarCluster.cpp
const int kControlTagSell = IMPERIALISM_FOURCC(
    'S', 'e', 'l', 'l'); // TAmtBar.cpp, TMacViewMgr.cpp, TTradeCluster.cpp...; 2 Mac screen(s)
const int kControlTagWind = IMPERIALISM_FOURCC('W', 'I', 'N', 'D'); // 76 Mac screen(s)
const int kControlTagAcce = IMPERIALISM_FOURCC('a', 'c', 'c', 'e'); // accept-offer hotspot
const int kControlTagAgr0 =
    IMPERIALISM_FOURCC('a', 'g', 'r', '0'); // first of 3 aggression-level buttons (agr0-agr2)
const int kControlTagArmy = IMPERIALISM_FOURCC(
    'a', 'r', 'm',
    'y'); // TArmyMgr.cpp, TBatRepDetLine.cpp, TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp...; 1 Mac screen(s)
const int kControlTagArmyRatioFirst =
    IMPERIALISM_FOURCC('a', 'r', 'r', '0'); // TArmyToolbar.cpp, TArmyUnitView.cpp; 1 Mac screen(s)
const int kControlTagAuto = IMPERIALISM_FOURCC('a', 'u', 't', 'o'); // all-AutoGP label
const int kControlTagBack = IMPERIALISM_FOURCC('b', 'a', 'c', 'k'); // dismiss/back button
const int kControlTagBar = IMPERIALISM_FOURCC(
    'b', 'a', 'r', ' '); // New-game setup screen tags (TRadioTextCluster option groups)
const int kControlTagBase = IMPERIALISM_FOURCC('b', 'a', 's', 'e'); // root-container tag
const int kControlTagCanc = IMPERIALISM_FOURCC('c', 'a', 'n', 'c'); // cancel hotspot (upper)
const int kControlTagCash = IMPERIALISM_FOURCC(
    'c', 'a', 's', 'h'); // TUniversityView.cpp, global_data_tables.cpp; 1 Mac screen(s)
const int kControlTagCgam =
    IMPERIALISM_FOURCC('c', 'g', 'a', 'm'); // TLoungeDialog.cpp, TMultiplayerMgr.cpp, TViewMgr.cpp
const int kControlTagChec = IMPERIALISM_FOURCC('c', 'h', 'e', 'c'); // ship-check hotspot
const int kControlTagCity = IMPERIALISM_FOURCC(
    'c', 'i', 't', 'y'); // TMapEditView.cpp, TToolBarCluster.cpp, TViewMgr.cpp; 8 Mac screen(s)
const int kControlTagClot = IMPERIALISM_FOURCC(
    'c', 'l', 'o',
    't'); // TCityProductionView.cpp, TIndustryView.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagCls0 =
    IMPERIALISM_FOURCC('c', 'l', 's', '0'); // first of the per-resource-type class sliders
const int kControlTagClus = IMPERIALISM_FOURCC('c', 'l', 'u', 's'); // generic cluster name tag
const int kControlTagCncl = IMPERIALISM_FOURCC('c', 'n', 'c', 'l'); // cancel hotspot (lower)
const int kControlTagCntl = IMPERIALISM_FOURCC('c', 'n', 't', 'l'); // generic control name tag
const int kControlTagCoat = IMPERIALISM_FOURCC('c', 'o', 'a', 't'); // coat-of-arms picture
const int kControlTagCoun = IMPERIALISM_FOURCC('c', 'o', 'u', 'n'); // country-name edit box
const int kControlTagCred = IMPERIALISM_FOURCC('c', 'r', 'e', 'd'); // credits text line 1
const int kControlTagCurs = IMPERIALISM_FOURCC('c', 'u', 'r', 's'); // cursor panel
const int kControlTagGOLD =
    IMPERIALISM_FOURCC('G', 'O', 'L', 'D'); // toolbar gold readout (uppercase in the binary)
const int kControlTagDeal =
    IMPERIALISM_FOURCC('d', 'e', 'a', 'l'); // foreign-minister "deal" button
const int kControlTagDesc = IMPERIALISM_FOURCC('d', 'e', 's', 'c'); // tech-item description picture
const int kControlTagDfnd = IMPERIALISM_FOURCC(
    'd', 'f', 'n',
    'd'); // TArmyToolbar.cpp, TCivToolbar.cpp, TNavyToolbarCluster.cpp...; 1 Mac screen(s)
const int kControlTagDif1 = IMPERIALISM_FOURCC('d', 'i', 'f', '1'); // Easy
const int kControlTagDif2 = IMPERIALISM_FOURCC('d', 'i', 'f', '2'); // Normal
const int kControlTagDif3 = IMPERIALISM_FOURCC('d', 'i', 'f', '3'); // Hard
const int kControlTagDif4 = IMPERIALISM_FOURCC('d', 'i', 'f', '4'); // Nigh-On Impossible
const int kControlTagDone = IMPERIALISM_FOURCC(
    'd', 'o', 'n',
    'e'); // TArmyToolbar.cpp, TCivToolbar.cpp, TGameScorePicture.cpp...; 5 Mac screen(s)
const int kControlTagEdit = IMPERIALISM_FOURCC('e', 'd', 'i', 't'); // edit-text name tag
const int kControlTagEnd = IMPERIALISM_FOURCC(
    'e', 'n', 'd',
    ' '); // TCouncilView.cpp, TDiplomacyMapView.cpp, TGameWindow.cpp...; 13 Mac screen(s)
const int kControlTagFish = IMPERIALISM_FOURCC(
    'f', 'i', 's', 'h'); // TIndustryView.cpp, global_data_tables.cpp; 2 Mac screen(s)
const int kControlTagFlag = IMPERIALISM_FOURCC('f', 'l', 'a', 'g'); // nation flag view
const int kSummaryTagFood = IMPERIALISM_FOURCC(
    'f', 'o', 'o', 'd'); // TIndustryView.cpp, TRailAmtBar.cpp, TRailCluster.cpp...; 5 Mac screen(s)
const int kControlTagForc =
    IMPERIALISM_FOURCC('f', 'o', 'r', 'c'); // TMapUberPicture.cpp, TToolBarCluster.cpp
const int kControlTagFurn = IMPERIALISM_FOURCC(
    'f', 'u', 'r',
    'n'); // TCityProductionView.cpp, TIndustryView.cpp, global_data_tables.cpp; 5 Mac screen(s)
const int kControlTagGd0Sp = IMPERIALISM_FOURCC(
    'g', 'd', '0',
    ' '); // TTradeCluster.cpp, TTraderAmtBar.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kControlTagGlob = IMPERIALISM_FOURCC('g', 'l', 'o', 'b'); // globe picture
const int kControlTagGrai = IMPERIALISM_FOURCC(
    'g', 'r', 'a',
    'i'); // TCityProductionView.cpp, TIndustryView.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kControlTagHard = IMPERIALISM_FOURCC(
    'h', 'a', 'r', 'd'); // TCityProductionView.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kControlTagHigh = IMPERIALISM_FOURCC('h', 'i', 'g', 'h'); // main-menu high-scores button
const int kControlTagHist = IMPERIALISM_FOURCC('h', 'i', 's', 't'); // historical names option
const int kControlTagInfo = IMPERIALISM_FOURCC('i', 'n', 'f', 'o'); // info text block
const int kControlTagItem = IMPERIALISM_FOURCC(
    'i', 't', 'e',
    'm'); // TBatRepDetLine.cpp, TNavyMgr.cpp, TTerrainHelpPicture.cpp; 1 Mac screen(s)
const int kControlTagLand = IMPERIALISM_FOURCC(
    'l', 'a', 'n',
    'd'); // TLandSaleEvent.cpp, TMultiplayerMgr.cpp, TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp
const int kControlTagLatr = IMPERIALISM_FOURCC(
    'l', 'a', 't', 'r'); // TArmyToolbar.cpp, TCivToolbar.cpp, TToggleButton.cpp; 1 Mac screen(s)
const int kControlTagLcor = IMPERIALISM_FOURCC('l', 'c', 'o', 'r'); // left-column control region
const int kControlTagLeft = IMPERIALISM_FOURCC(
    'l', 'e', 'f',
    't'); // TMacViewMgr.cpp, TShipyardCluster.cpp, TTradeCluster.cpp; 15 Mac screen(s)
const int kControlTagLoad = IMPERIALISM_FOURCC('l', 'o', 'a', 'd'); // main-menu load-game button
const int kControlTagLoca = IMPERIALISM_FOURCC('l', 'o', 'c', 'a'); // location text
const int kControlTagLost = IMPERIALISM_FOURCC(
    'l', 'o', 's', 't'); // TAutoGreatPower.cpp, THostGreatPower.cpp, TMultiplayerMgr.cpp...
const int kControlTagMain = IMPERIALISM_FOURCC('m', 'a', 'i', 'n'); // council ticker panel
const int kControlTagMapP = IMPERIALISM_FOURCC('m', 'a', 'p', ' '); // random-map preview view
const int kControlTagMerc =
    IMPERIALISM_FOURCC('m', 'e', 'r', 'c'); // foreign-minister "mercenaries" button
const int kControlTagMinu = IMPERIALISM_FOURCC(
    'm', 'i', 'n',
    'u'); // TArmyPlacard.cpp, TShipyardView.cpp, TUniversityView.cpp; 3 Mac screen(s)
const int kControlTagMmap = IMPERIALISM_FOURCC(
    'm', 'm', 'a', 'p'); // TMapUberPicture.cpp, TToolBarCluster.cpp; 1 Mac screen(s)
const int kControlTagMove = IMPERIALISM_FOURCC(
    'm', 'o', 'v',
    'e'); // TAmtBar.cpp, TAmtBarCluster.cpp, TIndustryCluster.cpp...; 12 Mac screen(s)
const int kControlTagMult = IMPERIALISM_FOURCC('m', 'u', 'l', 't'); // main-menu multiplayer button
const int kControlTagNada = IMPERIALISM_FOURCC('n', 'a', 'd', 'a'); // sentinel: no option selected
const int kControlTagNam0 = IMPERIALISM_FOURCC(
    'n', 'a', 'm', '0'); // TControl.cpp, TGPTreatyDialog.cpp, TLoungeDialog.cpp...; 5 Mac screen(s)
const int kControlTagNam1 = IMPERIALISM_FOURCC(
    'n', 'a', 'm',
    '1'); // TGPTreatyDialog.cpp, THelpPicture.cpp, TMinorTreatyDialog.cpp; 6 Mac screen(s)
const int kControlTagNam2 = IMPERIALISM_FOURCC(
    'n', 'a', 'm',
    '2'); // TGPTreatyDialog.cpp, THelpPicture.cpp, TMinorTreatyDialog.cpp; 6 Mac screen(s)
const int kControlTagNam3 = IMPERIALISM_FOURCC(
    'n', 'a', 'm',
    '3'); // TGPTreatyDialog.cpp, THelpPicture.cpp, TMinorTreatyDialog.cpp; 6 Mac screen(s)
const int kControlTagNam4 = IMPERIALISM_FOURCC(
    'n', 'a', 'm',
    '4'); // TGPTreatyDialog.cpp, THelpPicture.cpp, TMinorTreatyDialog.cpp; 6 Mac screen(s)
const int kControlTagNam5 = IMPERIALISM_FOURCC(
    'n', 'a', 'm',
    '5'); // TGPTreatyDialog.cpp, THelpPicture.cpp, TMinorTreatyDialog.cpp; 6 Mac screen(s)
const int kControlTagNam6 = IMPERIALISM_FOURCC(
    'n', 'a', 'm',
    '6'); // TGPTreatyDialog.cpp, THelpPicture.cpp, TLoungeDialog.cpp...; 5 Mac screen(s)
const int kControlTagName = IMPERIALISM_FOURCC('n', 'a', 'm', 'e'); // names radio cluster
const int kControlTagNewg =
    IMPERIALISM_FOURCC('n', 'e', 'w', 'g'); // flag-options "new game" hotspot
const int kControlTagNext = IMPERIALISM_FOURCC('n', 'e', 'x', 't'); // next-selection hotspot
const int kControlTagNuma = IMPERIALISM_FOURCC(
    'n', 'u', 'm', 'a'); // TGameScorePicture.cpp, TMapUberPicture.cpp; 2 Mac screen(s)
const int kControlTagNumb = IMPERIALISM_FOURCC(
    'n', 'u', 'm', 'b'); // TArmoryView.cpp, TShipyardView.cpp, TUniversityView.cpp; 5 Mac screen(s)
const int kControlTagOffr = IMPERIALISM_FOURCC(
    'o', 'f', 'f',
    'r'); // TTradeCluster.cpp, TTradeOrderPicture.cpp, global_data_tables.cpp; 3 Mac screen(s)
const int kControlTagOkay = IMPERIALISM_FOURCC('o', 'k', 'a', 'y'); // confirm button
const int kControlTagOne1 = IMPERIALISM_FOURCC(
    'o', 'n', 'e', '1'); // TSetupRandomMapPicture.cpp, TViewMgr.cpp; 1 Mac screen(s)
const int kControlTagOpt1 = IMPERIALISM_FOURCC(
    'o', 'p', 't', '1'); // TToggleButton.cpp, TToolBarCluster.cpp; 1 Mac screen(s)
const int kControlTagPage = IMPERIALISM_FOURCC(
    'p', 'a', 'g',
    'e'); // TBook.cpp, TCombatReportView.cpp, TSuperArmyRoster.cpp...; 5 Mac screen(s)
const int kControlTagPatc = IMPERIALISM_FOURCC('p', 'a', 't', 'c'); // patch picture
const int kControlTagPick = IMPERIALISM_FOURCC(
    'p', 'i', 'c', 'k'); // TLoungeDialog.cpp, TMapPreviewView.cpp, TScenarioChooser.cpp...
const int kControlTagPict = IMPERIALISM_FOURCC('p', 'i', 'c', 't'); // generic picture name tag
const int kControlTagPlan = IMPERIALISM_FOURCC(
    'p', 'l', 'a', 'n'); // TSetupRandomMapPicture.cpp, TViewMgr.cpp; 1 Mac screen(s)
const int kControlTagPlus = IMPERIALISM_FOURCC(
    'p', 'l', 'u', 's'); // TArmoryView.cpp, TArmyPlacard.cpp, TShipyardView.cpp...; 3 Mac screen(s)
const int kControlTagPreviewMap = IMPERIALISM_FOURCC(
    'p', 'm', 'a',
    'p'); // Turn-event trade-board builder tags (previously raw MISSING-TAG literals)
const int kControlTagPort =
    IMPERIALISM_FOURCC('p', 'o', 'r', 't'); // TCivMgr.cpp, global_data_tables.cpp; 1 Mac screen(s)
const int kSummaryTagPowe = IMPERIALISM_FOURCC(
    'p', 'o', 'w',
    'e'); // TCityProductionView.cpp, TRailAmtBar.cpp, TRailCluster.cpp; 3 Mac screen(s)
const int kControlTagPref = IMPERIALISM_FOURCC('p', 'r', 'e', 'f'); // main-menu preferences button
const int kControlTagPrev = IMPERIALISM_FOURCC(
    'p', 'r', 'e', 'v'); // TBattleReportView.cpp, THelpPicture.cpp; 2 Mac screen(s)
const int kControlTagPric =
    IMPERIALISM_FOURCC('p', 'r', 'i', 'c'); // foreign-minister "price" button
const int kControlTagProd = IMPERIALISM_FOURCC(
    'p', 'r', 'o',
    'd'); // TCityProductionView.cpp, TIndustryView.cpp, global_data_tables.cpp; 4 Mac screen(s)
const int kSummaryTagProf = IMPERIALISM_FOURCC(
    'p', 'r', 'o',
    'f'); // TCityBarCluster.cpp, TCityProductionView.cpp, TRailAmtBar.cpp...; 2 Mac screen(s)
const int kControlTagProt = IMPERIALISM_FOURCC('p', 'r', 'o', 't'); // network protocol option field
const int kControlTagProv = IMPERIALISM_FOURCC(
    'p', 'r', 'o', 'v'); // TIndustryView.cpp, global_data_tables.cpp; 2 Mac screen(s)
const int kControlTagQuer = IMPERIALISM_FOURCC(
    'q', 'u', 'e',
    'r'); // TBattleReportView.cpp, TCitySiteView.cpp, TCouncilView.cpp...; 16 Mac screen(s)
const int kControlTagQuit = IMPERIALISM_FOURCC('q', 'u', 'i', 't'); // main-menu quit button
const int kSummaryTagRail = IMPERIALISM_FOURCC(
    'r', 'a', 'i', 'l'); // TCivMgr.cpp, TRailAmtBar.cpp, TRailCluster.cpp...; 2 Mac screen(s)
const int kControlTagRand = IMPERIALISM_FOURCC('r', 'a', 'n', 'd'); // main-menu random-map button
const int kControlTagRcor = IMPERIALISM_FOURCC('r', 'c', 'o', 'r'); // right-column control region
const int kControlTagRecc =
    IMPERIALISM_FOURCC('r', 'e', 'c', 'c'); // interior-minister "reconstruction" button
const int kControlTagReje = IMPERIALISM_FOURCC('r', 'e', 'j', 'e'); // reject-offer hotspot
const int kControlTagRela =
    IMPERIALISM_FOURCC('r', 'e', 'l', 'a'); // TToggleButton.cpp, global_data_tables.cpp
const int kControlTagRetr = IMPERIALISM_FOURCC('r', 'e', 't', 'r'); // tactical retreat button
const int kControlTagRght = IMPERIALISM_FOURCC('r', 'g', 'h', 't'); // Display manager control tags
const int kControlTagSave =
    IMPERIALISM_FOURCC('s', 'a', 'v', 'e'); // flag-options "save game" hotspot
const int kControlTagScen = IMPERIALISM_FOURCC('s', 'c', 'e', 'n'); // main-menu scenario button
const int kControlTagScro =
    IMPERIALISM_FOURCC('s', 'c', 'r', 'o'); // TScrollView.cpp, TTreatiesView.cpp; 1 Mac screen(s)
const int kControlTagSanc =
    IMPERIALISM_FOURCC('s', 'a', 'n', 'c'); // diplomacy sanction toggle (TDipDlgCluster)
const int kControlTagSeas = IMPERIALISM_FOURCC('s', 'e', 'a', 's'); // season label
const int kControlTagSele = IMPERIALISM_FOURCC(
    's', 'e', 'l',
    'e'); // TArmoryView.cpp, TMultiplayerMgr.cpp, TShipyardView.cpp...; 3 Mac screen(s)
const int kControlTagShip = IMPERIALISM_FOURCC('s', 'h', 'i', 'p'); // ship-fraction icon control
const int kControlTagStar = IMPERIALISM_FOURCC(
    's', 't', 'a',
    'r'); // TCouncilView.cpp, TMultiplayerMgr.cpp, TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp...; 1 Mac screen(s)
const int kControlTagStat = IMPERIALISM_FOURCC('s', 't', 'a', 't'); // static-text name tag
const int kControlTagTab0 = IMPERIALISM_FOURCC(
    't', 'a', 'b', '0'); // first of 7 sequential score-graph nation tabs (tab0-tab6)
const int kControlTagTarg = IMPERIALISM_FOURCC('t', 'a', 'r', 'g'); // tactical target button
const int kControlTagTbr1 = IMPERIALISM_FOURCC(
    't', 'b', 'r',
    '1'); // TArmyUnitView.cpp, TMapUberPicture.cpp, TMiniArmyView.cpp...; 1 Mac screen(s)
const int kControlTagTbr2 = IMPERIALISM_FOURCC('t', 'b', 'r', '2'); // secondary toolbar
const int kControlTagTevw = IMPERIALISM_FOURCC('t', 'e', 'v', 'w'); // text-view name tag
const int kControlTagText = IMPERIALISM_FOURCC(
    't', 'e', 'x', 't'); // TMacViewMgr.cpp, TOffersPanelView.cpp, TViewMgr.cpp; 5 Mac screen(s)
const int kControlTagTime = IMPERIALISM_FOURCC(
    't', 'i', 'm', 'e'); // NetMessage.cpp, TClientGreatPower.cpp, TMultiplayerMgr.cpp...
const int kControlTagTitL = IMPERIALISM_FOURCC(
    't', 'i', 't', 'L'); // trade-book title (uppercase-L variant, distinct from kControlTagTitl)
const int kControlTagTitR =
    IMPERIALISM_FOURCC('t', 'i', 't', 'R'); // transport-ledger right-column title
const int kControlTagTitl = IMPERIALISM_FOURCC('t', 'i', 't', 'l'); // title text
const int kControlTagTnam = IMPERIALISM_FOURCC('t', 'n', 'a', 'm'); // names title label
const int kControlTagTool = IMPERIALISM_FOURCC(
    't', 'o', 'o',
    'l'); // TArmyBattle.cpp, TDealBookPicture.cpp, TMapUberPicture.cpp...; 19 Mac screen(s)
const int kControlTagTop = IMPERIALISM_FOURCC('t', 'o', 'p', ' '); // top picture
const int kControlTagTopB =
    IMPERIALISM_FOURCC('t', 'o', 'p', 'B'); // TDiplomacyMapView.cpp, TViewMgr.cpp; 6 Mac screen(s)
const int kControlTagTota =
    IMPERIALISM_FOURCC('t', 'o', 't', 'a'); // TMacViewMgr.cpp, TTransportView.cpp; 1 Mac screen(s)
const int kControlTagTrad = IMPERIALISM_FOURCC(
    't', 'r', 'a',
    'd'); // TMultiplayerMgr.cpp, TProxyGreatPower.cpp, TToolBarCluster.cpp...; 8 Mac screen(s)
const int kSummaryTagTrai =
    IMPERIALISM_FOURCC('t', 'r', 'a', 'i'); // trade-summary industrial-art row; the bytes are trai
const int kControlTagTran = IMPERIALISM_FOURCC(
    't', 'r', 'a',
    'n'); // TInteriorMinisterView.cpp, TToolBarCluster.cpp, TTransportView.cpp...; 8 Mac screen(s)
const int kControlTagTrea = IMPERIALISM_FOURCC('t', 'r', 'e', 'a'); // treasury label
const int kControlTagTree = IMPERIALISM_FOURCC(
    't', 'r', 'e', 'e'); // TMapUberPicture.cpp, TToolBarCluster.cpp; 1 Mac screen(s)
const int kControlTagUarm = IMPERIALISM_FOURCC(
    'u', 'a', 'r', 'm'); // TCityProductionView.cpp, TMapUberPicture.cpp; 1 Mac screen(s)
const int kControlTagUnit =
    IMPERIALISM_FOURCC('u', 'n', 'i', 't'); // TCivToolbar.cpp, TUniversityView.cpp; 5 Mac screen(s)
const int kControlTagUntr = IMPERIALISM_FOURCC(
    'u', 'n', 't', 'r'); // TCityBarCluster.cpp, TCityProductionView.cpp; 1 Mac screen(s)
const int kControlTagUpgr = IMPERIALISM_FOURCC('u', 'p', 'g', 'r'); // mini-army upgrade hotspot
const int kControlTagValu =
    IMPERIALISM_FOURCC('v', 'a', 'l', 'u'); // purchase-cluster numeric value control
const int kControlTagYear = IMPERIALISM_FOURCC(
    'y', 'e', 'a',
    'r'); // TMapUberPicture.cpp, TToolBarCluster.cpp, global_data_tables.cpp; 1 Mac screen(s)
const int kControlTagZone = IMPERIALISM_FOURCC(
    'z', 'o', 'n', 'e'); // TMapUberPicture.cpp, global_data_tables.cpp; 3 Mac screen(s)
