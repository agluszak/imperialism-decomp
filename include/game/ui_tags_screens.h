#pragma once

#include "game/ui_fourcc.h"

// Four-character tags application, setup, and standalone screens.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kControlTagNASA = IMPERIALISM_FOURCC('N', 'A', 'S', 'A'); // TSetupRandomMapPicture.cpp
const int kControlTagTERM = IMPERIALISM_FOURCC('T', 'E', 'R', 'M'); // TSimMgr.cpp
const int kControlTagAdvi =
    IMPERIALISM_FOURCC('a', 'd', 'v', 'i'); // query-floater "advisor" hotspot
const int kControlTagAlli = IMPERIALISM_FOURCC('a', 'l', 'l', 'i'); // TToggleButton.cpp
const int kControlTagBatt =
    IMPERIALISM_FOURCC('b', 'a', 't', 't'); // query-floater "declare war"/battle hotspot
const int kControlTagChar =
    IMPERIALISM_FOURCC('c', 'h', 'a', 'r'); // query-floater "chart"/graph hotspot
const int kControlTagCountryDescription =
    IMPERIALISM_FOURCC('c', 'd', 'e', 's'); // scenario chooser nation description
const int kControlTagClnc =
    IMPERIALISM_FOURCC('c', 'l', 'n', 'c'); // query-floater cancel hotspot (lower)
const int kControlTagCre2 = IMPERIALISM_FOURCC('c', 'r', 'e', '2'); // credits text line 2
const int kControlTagDate =
    IMPERIALISM_FOURCC('d', 'a', 't', 'e'); // TNewspaperView.cpp; 1 Mac screen(s)
const int kControlTagDif0 = IMPERIALISM_FOURCC('d', 'i', 'f', '0'); // Introductory
const int kControlTagDiff = IMPERIALISM_FOURCC('d', 'i', 'f', 'f'); // difficulty radio cluster
const int kControlTagDift = IMPERIALISM_FOURCC('d', 'i', 'f', 't'); // difficulty title label
const int kControlTagDonf = IMPERIALISM_FOURCC('d', 'o', 'n', 'f'); // TToggleButton.cpp
const int kControlTagDont = IMPERIALISM_FOURCC('d', 'o', 'n', 't'); // TPageView.cpp
const int kControlTagEmpi = IMPERIALISM_FOURCC('e', 'm', 'p', 'i'); // TToggleButton.cpp
const int kControlTagEmpj = IMPERIALISM_FOURCC('e', 'm', 'p', 'j'); // TToggleButton.cpp
const int kControlTagExit =
    IMPERIALISM_FOURCC('e', 'x', 'i', 't'); // TScenarioChooser.cpp; 1 Mac screen(s)
const int kControlTagFGP0 = IMPERIALISM_FOURCC('f', 'G', 'P', '0'); // TToggleButton.cpp
const int kControlTagFGP6 = IMPERIALISM_FOURCC('f', 'G', 'P', '6'); // TToggleButton.cpp
const int kControlTagGame = IMPERIALISM_FOURCC('g', 'a', 'm', 'e'); // join-selector game-name field
const int kControlTagHost = IMPERIALISM_FOURCC('h', 'o', 's', 't'); // host-a-new-game hotspot
const int kControlTagHot = IMPERIALISM_FOURCC('h', 'o', 't', '!');  // hint/info bar text
const int kControlTagI00a =
    IMPERIALISM_FOURCC('i', '0', '0', 'a'); // first of 12 tile context-menu item panes (i00a-i00l)
const int kControlTagI00m =
    IMPERIALISM_FOURCC('i', '0', '0', 'm'); // exclusive upper bound of the i00a-i00l range
const int kControlTagJoin = IMPERIALISM_FOURCC('j', 'o', 'i', 'n'); // join-a-game hotspot
const int kControlTagKeyP = IMPERIALISM_FOURCC('k', 'e', 'y', ' '); // map-key hotspot
const int kControlTagList =
    IMPERIALISM_FOURCC('l', 'i', 's', 't'); // TScenarioChooser.cpp; 3 Mac screen(s)
const int kControlTagMore = IMPERIALISM_FOURCC(
    'm', 'o', 'r', 'e'); // THelpPicture.cpp, TScenarioChooser.cpp; 2 Mac screen(s)
const int kControlTagMovf = IMPERIALISM_FOURCC('m', 'o', 'v', 'f'); // TToggleButton.cpp
const int kControlTagNews = IMPERIALISM_FOURCC('n', 'e', 'w', 's'); // query-floater "news" hotspot
const int kControlTagNonA = IMPERIALISM_FOURCC('n', 'o', 'n', 'A'); // TToggleButton.cpp
const int kControlTagNonB = IMPERIALISM_FOURCC('n', 'o', 'n', 'B'); // TToggleButton.cpp
const int kControlTagOpt5 = IMPERIALISM_FOURCC('o', 'p', 't', '5'); // TToggleButton.cpp
const int kControlTagOref = IMPERIALISM_FOURCC(
    'o', 'r', 'e', 'f'); // query-floater foreign-affairs hotspot; the bytes are oref
const int kControlTagOtto =
    IMPERIALISM_FOURCC('o', 't', 't', 'o'); // TLoadSavePicture.cpp; 1 Mac screen(s)
const int kControlTagPagf = IMPERIALISM_FOURCC('p', 'a', 'g', 'f'); // TBook.cpp; 1 Mac screen(s)
const int kControlTagPtfr =
    IMPERIALISM_FOURCC('p', 't', 'f', 'r'); // TGameScorePicture.cpp; 1 Mac screen(s)
const int kControlTagScdn = IMPERIALISM_FOURCC('s', 'c', 'd', 'n'); // TScrollBarView.cpp
const int kControlTagScn0 =
    IMPERIALISM_FOURCC('s', 'c', 'n', '0'); // TGameSetupMultiplayerPicture.cpp, TMultiplayerMgr.cpp
const int kControlTagScenarioDescription =
    IMPERIALISM_FOURCC('s', 'd', 'e', 's'); // scenario chooser scenario description
const int kControlTagScra =
    IMPERIALISM_FOURCC('s', 'c', 'r', 'a'); // TGameScorePicture.cpp; 1 Mac screen(s)
const int kControlTagScup = IMPERIALISM_FOURCC('s', 'c', 'u', 'p'); // TScrollBarView.cpp
const int kControlTagSlot = IMPERIALISM_FOURCC('s', 'l', 'o', 't'); // TLoadSavePicture.cpp
const int kControlTagSlt0 =
    IMPERIALISM_FOURCC('s', 'l', 't', '0'); // TLoadSavePicture.cpp; 1 Mac screen(s)
const int kControlTagSpec =
    IMPERIALISM_FOURCC('s', 'p', 'e', 'c'); // TNewspaperView.cpp; 1 Mac screen(s)
const int kControlTagSpit =
    IMPERIALISM_FOURCC('s', 'p', 'i', 't'); // resume-pending-session hotspot
const int kControlTagStuf = IMPERIALISM_FOURCC('s', 't', 'u', 'f'); // right-hand settings cluster
const int kControlTagSubj =
    IMPERIALISM_FOURCC('s', 'u', 'b', 'j'); // THelpPicture.cpp; 1 Mac screen(s)
const int kControlTagSwin =
    IMPERIALISM_FOURCC('s', 'w', 'i', 'n'); // THelpPicture.cpp; 1 Mac screen(s)
const int kControlTagTcou = IMPERIALISM_FOURCC('t', 'c', 'o', 'u'); // country title label
const int kControlTagTex0 =
    IMPERIALISM_FOURCC('t', 'e', 'x', '0'); // first of 7 sequential text lines (tex0-tex6)
const int kControlTagTil2 = IMPERIALISM_FOURCC(
    't', 'i', 'l', '2'); // TLonelyTileView.cpp, TTerrainHelpPicture.cpp; 1 Mac screen(s)
const int kControlTagTile = IMPERIALISM_FOURCC(
    't', 'i', 'l', 'e'); // TLonelyTileView.cpp, TTerrainHelpPicture.cpp; 1 Mac screen(s)
const int kControlTagTogl =
    IMPERIALISM_FOURCC('t', 'o', 'g', 'l'); // THelpPicture.cpp; 1 Mac screen(s)
const int kControlTagTpol = IMPERIALISM_FOURCC('t', 'p', 'o', 'l'); // TToggleButton.cpp
const int kControlTagUClu = IMPERIALISM_FOURCC('u', 'C', 'l', 'u'); // TToggleButton.cpp
const int kControlTagVict =
    IMPERIALISM_FOURCC('v', 'i', 'c', 't'); // TGameScorePicture.cpp; 1 Mac screen(s)
const int kControlTagWarSp = IMPERIALISM_FOURCC('w', 'a', 'r', ' '); // TToggleButton.cpp
