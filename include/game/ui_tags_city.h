#pragma once

#include "game/ui_fourcc.h"

// Four-character tags city, industry, and trade screens.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kControlTagForM =
    IMPERIALISM_FOURCC('F', 'o', 'r', 'M'); // trade-desk detail-level toggle
const int kControlTagNnkParen = IMPERIALISM_FOURCC('N', 'n', 'k', '('); // TCityInteriorMinister.cpp
const int kControlTagAexp =
    IMPERIALISM_FOURCC('a', 'e', 'x', 'p'); // TUniversityView.cpp; 1 Mac screen(s)
const int kControlTagApap =
    IMPERIALISM_FOURCC('a', 'p', 'a', 'p'); // TUniversityView.cpp; 1 Mac screen(s)
const int kControlTagAva0 =
    IMPERIALISM_FOURCC('a', 'v', 'a', '0'); // TArmoryView.cpp; 1 Mac screen(s)
const int kControlTagAva1 =
    IMPERIALISM_FOURCC('a', 'v', 'a', '1'); // TArmoryView.cpp; 1 Mac screen(s)
const int kControlTagAva2 =
    IMPERIALISM_FOURCC('a', 'v', 'a', '2'); // TArmoryView.cpp; 1 Mac screen(s)
const int kControlTagAva3 =
    IMPERIALISM_FOURCC('a', 'v', 'a', '3'); // TArmoryView.cpp; 1 Mac screen(s)
const int kControlTagBook = IMPERIALISM_FOURCC('b', 'o', 'o', 'k'); // offer-desk book control
const int kControlTagBoug =
    IMPERIALISM_FOURCC('b', 'o', 'u', 'g'); // TDealBookPicture.cpp; 1 Mac screen(s)
const int kControlTagBut0 =
    IMPERIALISM_FOURCC('b', 'u', 't', '0'); // TShipyardView.cpp; 1 Mac screen(s)
const int kControlTagCapT =
    IMPERIALISM_FOURCC('c', 'a', 'p', 'T'); // TIndustryView.cpp; 10 Mac screen(s)
const int kControlTagCexp =
    IMPERIALISM_FOURCC('c', 'e', 'x', 'p'); // TUniversityView.cpp; 1 Mac screen(s)
const int kControlTagChoi = IMPERIALISM_FOURCC('c', 'h', 'o', 'i'); // TRailheadDialog.cpp
const int kControlTagCiv0 =
    IMPERIALISM_FOURCC('c', 'i', 'v', '0'); // TArmoryView.cpp, TUniversityView.cpp; 2 Mac screen(s)
const int kControlTagClu0 = IMPERIALISM_FOURCC(
    'c', 'l', 'u', '0'); // TShipyardView.cpp, TUniversityView.cpp; 3 Mac screen(s)
const int kControlTagCos1 =
    IMPERIALISM_FOURCC('c', 'o', 's', '1'); // TTradeSchoolView.cpp; 2 Mac screen(s)
const int kControlTagCos2 =
    IMPERIALISM_FOURCC('c', 'o', 's', '2'); // TTradeSchoolView.cpp; 2 Mac screen(s)
const int kControlTagCpap =
    IMPERIALISM_FOURCC('c', 'p', 'a', 'p'); // TUniversityView.cpp; 1 Mac screen(s)
const int kControlTagEqu1 =
    IMPERIALISM_FOURCC('e', 'q', 'u', '1'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagEqu2 =
    IMPERIALISM_FOURCC('e', 'q', 'u', '2'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagEqu3 =
    IMPERIALISM_FOURCC('e', 'q', 'u', '3'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagEqu4 =
    IMPERIALISM_FOURCC('e', 'q', 'u', '4'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagEqu5 =
    IMPERIALISM_FOURCC('e', 'q', 'u', '5'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagEqua =
    IMPERIALISM_FOURCC('e', 'q', 'u', 'a'); // TIndustryView.cpp; 11 Mac screen(s)
const int kControlTagExpa = IMPERIALISM_FOURCC('e', 'x', 'p', 'a'); // expand-industry hotspot
const int kControlTagFix0 = IMPERIALISM_FOURCC(
    'f', 'i', 'x', '0'); // TShipyardView.cpp, TUniversityView.cpp; 2 Mac screen(s)
const int kControlTagFix2 =
    IMPERIALISM_FOURCC('f', 'i', 'x', '2'); // TUniversityView.cpp; 1 Mac screen(s)
const int kControlTagFort = IMPERIALISM_FOURCC('f', 'o', 'r', 't'); // TCivMgr.cpp; 1 Mac screen(s)
const int kControlTagIcon =
    IMPERIALISM_FOURCC('i', 'c', 'o', 'n'); // TUnitsView.cpp; 1 Mac screen(s)
const int kControlTagLabP =
    IMPERIALISM_FOURCC('l', 'a', 'b', 'P'); // TCityProductionView.cpp; 1 Mac screen(s)
const int kControlTagLabV =
    IMPERIALISM_FOURCC('l', 'a', 'b', 'V'); // TIndustryView.cpp; 9 Mac screen(s)
const int kControlTagLaro =
    IMPERIALISM_FOURCC('l', 'a', 'r', 'o'); // purchase-amount decrement arrow
const int kControlTagMark =
    IMPERIALISM_FOURCC('m', 'a', 'r', 'k'); // TDealBookPicture.cpp; 1 Mac screen(s)
const int kControlTagMeat =
    IMPERIALISM_FOURCC('m', 'e', 'a', 't'); // TCityProductionView.cpp; 1 Mac screen(s)
const int kControlTagMon1 =
    IMPERIALISM_FOURCC('m', 'o', 'n', '1'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagMon2 =
    IMPERIALISM_FOURCC('m', 'o', 'n', '2'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagNum0 =
    IMPERIALISM_FOURCC('n', 'u', 'm', '0'); // TArmoryView.cpp, TUniversityView.cpp; 3 Mac screen(s)
const int kControlTagOrSpSp =
    IMPERIALISM_FOURCC('o', 'r', ' ', ' '); // TIndustryView.cpp; 5 Mac screen(s)
const int kControlTagPap1 =
    IMPERIALISM_FOURCC('p', 'a', 'p', '1'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagPap2 =
    IMPERIALISM_FOURCC('p', 'a', 'p', '2'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagPlaq =
    IMPERIALISM_FOURCC('p', 'l', 'a', 'q'); // TArmoryView.cpp; 1 Mac screen(s)
const int kControlTagRaro =
    IMPERIALISM_FOURCC('r', 'a', 'r', 'o'); // purchase-amount increment arrow
const int kControlTagRtil = IMPERIALISM_FOURCC('r', 't', 'i', 'l'); // trade-book season/year label
const int kControlTagSnam =
    IMPERIALISM_FOURCC('s', 'n', 'a', 'm'); // TShipyardView.cpp; 1 Mac screen(s)
const int kControlTagSold =
    IMPERIALISM_FOURCC('s', 'o', 'l', 'd'); // TDealBookPicture.cpp; 1 Mac screen(s)
const int kControlTagSpic =
    IMPERIALISM_FOURCC('s', 'p', 'i', 'c'); // TShipyardView.cpp; 1 Mac screen(s)
const int kControlTagSta0 =
    IMPERIALISM_FOURCC('s', 't', 'a', '0'); // TShipyardView.cpp; 1 Mac screen(s)
const int kControlTagSupp = IMPERIALISM_FOURCC('s', 'u', 'p', 'p'); // TTransportView.cpp
const int kControlTagSust =
    IMPERIALISM_FOURCC('s', 'u', 's', 't'); // TPlaceCityDialog.cpp; 1 Mac screen(s)
const int kControlTagTabs =
    IMPERIALISM_FOURCC('t', 'a', 'b', 's'); // TDealBookPicture.cpp; 2 Mac screen(s)
const int kControlTagTari = IMPERIALISM_FOURCC('t', 'a', 'r', 'i'); // TCityProductionView.cpp
const int kControlTagTbou = IMPERIALISM_FOURCC('t', 'b', 'o', 'u'); // trade-book control region
const int kControlTagTraV =
    IMPERIALISM_FOURCC('t', 'r', 'a', 'V'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagTsol = IMPERIALISM_FOURCC('t', 's', 'o', 'l'); // trade-book control region
const int kControlTagUntV =
    IMPERIALISM_FOURCC('u', 'n', 't', 'V'); // TTradeSchoolView.cpp; 1 Mac screen(s)
const int kControlTagUshi = IMPERIALISM_FOURCC('u', 's', 'h', 'i'); // TCityProductionView.cpp
const int kControlTagUuni = IMPERIALISM_FOURCC('u', 'u', 'n', 'i'); // TCityProductionView.cpp
const int kControlTagMPic =
    IMPERIALISM_FOURCC('m', 'P', 'i', 'c'); // TOfferDeskPicture.cpp mini picture
const int kControlTagShee = IMPERIALISM_FOURCC(
    's', 'h', 'e', 'e'); // TOfferDeskPicture.cpp, TOffersPanelView.cpp offer sheet
const int kControlTagWait = IMPERIALISM_FOURCC(
    'w', 'a', 'i', 't'); // TOfferDeskPicture.cpp, TOffersPanelView.cpp waiting indicator
const int kControlTagCrup =
    IMPERIALISM_FOURCC('c', 'r', 'u', 'p'); // TOfferDeskPicture.cpp cancel/close-proposal control
const int kControlTagNomo =
    IMPERIALISM_FOURCC('n', 'o', 'm', 'o'); // TOfferDeskPicture.cpp no-more-offers control
