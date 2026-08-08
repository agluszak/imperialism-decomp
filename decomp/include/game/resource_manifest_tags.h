#pragma once

#include "game/ui_fourcc.h"

// Four-character tags generated resource-manifest entries.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kManifestTagAUT0 = IMPERIALISM_FOURCC('A', 'U', 'T', '0'); // global_data_tables.cpp
const int kManifestTagGP0Sp =
    IMPERIALISM_FOURCC('G', 'P', '0', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagGP1Sp =
    IMPERIALISM_FOURCC('G', 'P', '1', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagGP2Sp =
    IMPERIALISM_FOURCC('G', 'P', '2', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagGP3Sp =
    IMPERIALISM_FOURCC('G', 'P', '3', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagGP4Sp =
    IMPERIALISM_FOURCC('G', 'P', '4', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagGP5Sp =
    IMPERIALISM_FOURCC('G', 'P', '5', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagGP6Sp =
    IMPERIALISM_FOURCC('G', 'P', '6', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagArma =
    IMPERIALISM_FOURCC('a', 'r', 'm', 'a'); // global_data_tables.cpp; 2 Mac screen(s)
const int kManifestTagCapa = IMPERIALISM_FOURCC('c', 'a', 'p', 'a'); // global_data_tables.cpp
const int kManifestTagCivi = IMPERIALISM_FOURCC('c', 'i', 'v', 'i'); // global_data_tables.cpp
const int kManifestTagCnam = IMPERIALISM_FOURCC('c', 'n', 'a', 'm'); // global_data_tables.cpp
const int kManifestTagCoal =
    IMPERIALISM_FOURCC('c', 'o', 'a', 'l'); // global_data_tables.cpp; 5 Mac screen(s)
const int kManifestTagCott =
    IMPERIALISM_FOURCC('c', 'o', 't', 't'); // global_data_tables.cpp; 6 Mac screen(s)
const int kControlTagCout =
    IMPERIALISM_FOURCC('c', 'o', 'u', 't'); // diplomacy-map "council" button hover-text variant
const int kManifestTagDeve = IMPERIALISM_FOURCC('d', 'e', 'v', 'e'); // global_data_tables.cpp
const int kManifestTagEmba = IMPERIALISM_FOURCC('e', 'm', 'b', 'a'); // global_data_tables.cpp
const int kManifestTagFabr =
    IMPERIALISM_FOURCC('f', 'a', 'b', 'r'); // global_data_tables.cpp; 6 Mac screen(s)
const int kManifestTagFuel =
    IMPERIALISM_FOURCC('f', 'u', 'e', 'l'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagGems =
    IMPERIALISM_FOURCC('g', 'e', 'm', 's'); // global_data_tables.cpp; 1 Mac screen(s)
const int kManifestTagGold =
    IMPERIALISM_FOURCC('g', 'o', 'l', 'd'); // global_data_tables.cpp; 1 Mac screen(s)
const int kControlTagGran =
    IMPERIALISM_FOURCC('g', 'r', 'a', 'n'); // diplomacy-map "grants" action button
const int kControlTagGrat =
    IMPERIALISM_FOURCC('g', 'r', 'a', 't'); // diplomacy-map "grants" button hover-text variant
const int kManifestTagHors =
    IMPERIALISM_FOURCC('h', 'o', 'r', 's'); // global_data_tables.cpp; 2 Mac screen(s)
const int kControlTagInft =
    IMPERIALISM_FOURCC('i', 'n', 'f', 't'); // diplomacy-map "info" button hover-text variant
const int kManifestTagIron =
    IMPERIALISM_FOURCC('i', 'r', 'o', 'n'); // global_data_tables.cpp; 5 Mac screen(s)
const int kManifestTagLabo =
    IMPERIALISM_FOURCC('l', 'a', 'b', 'o'); // global_data_tables.cpp; 1 Mac screen(s)
const int kManifestTagLive =
    IMPERIALISM_FOURCC('l', 'i', 'v', 'e'); // global_data_tables.cpp; 1 Mac screen(s)
const int kManifestTagLumb =
    IMPERIALISM_FOURCC('l', 'u', 'm', 'b'); // global_data_tables.cpp; 7 Mac screen(s)
const int kManifestTagM10Sp =
    IMPERIALISM_FOURCC('m', '1', '0', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM11Sp =
    IMPERIALISM_FOURCC('m', '1', '1', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM12Sp =
    IMPERIALISM_FOURCC('m', '1', '2', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM13Sp =
    IMPERIALISM_FOURCC('m', '1', '3', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM14Sp =
    IMPERIALISM_FOURCC('m', '1', '4', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM15Sp =
    IMPERIALISM_FOURCC('m', '1', '5', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM16Sp =
    IMPERIALISM_FOURCC('m', '1', '6', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM17Sp =
    IMPERIALISM_FOURCC('m', '1', '7', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM18Sp =
    IMPERIALISM_FOURCC('m', '1', '8', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM19Sp =
    IMPERIALISM_FOURCC('m', '1', '9', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM20Sp =
    IMPERIALISM_FOURCC('m', '2', '0', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM21Sp =
    IMPERIALISM_FOURCC('m', '2', '1', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM22Sp =
    IMPERIALISM_FOURCC('m', '2', '2', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM7SpSp =
    IMPERIALISM_FOURCC('m', '7', ' ', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM8SpSp =
    IMPERIALISM_FOURCC('m', '8', ' ', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagM9SpSp =
    IMPERIALISM_FOURCC('m', '9', ' ', ' '); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagOilSp =
    IMPERIALISM_FOURCC('o', 'i', 'l', ' '); // global_data_tables.cpp; 5 Mac screen(s)
const int kManifestTagPape =
    IMPERIALISM_FOURCC('p', 'a', 'p', 'e'); // global_data_tables.cpp; 2 Mac screen(s)
const int kManifestTagPnam = IMPERIALISM_FOURCC('p', 'n', 'a', 'm'); // global_data_tables.cpp
const int kManifestTagRGP0 =
    IMPERIALISM_FOURCC('r', 'G', 'P', '0'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagRGP1 =
    IMPERIALISM_FOURCC('r', 'G', 'P', '1'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagRGP2 =
    IMPERIALISM_FOURCC('r', 'G', 'P', '2'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagRGP3 =
    IMPERIALISM_FOURCC('r', 'G', 'P', '3'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagRGP4 =
    IMPERIALISM_FOURCC('r', 'G', 'P', '4'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagRGP5 =
    IMPERIALISM_FOURCC('r', 'G', 'P', '5'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagRGP6 =
    IMPERIALISM_FOURCC('r', 'G', 'P', '6'); // global_data_tables.cpp; 4 Mac screen(s)
const int kManifestTagStee =
    IMPERIALISM_FOURCC('s', 't', 'e', 'e'); // global_data_tables.cpp; 7 Mac screen(s)
const int kManifestTagSubs = IMPERIALISM_FOURCC('s', 'u', 'b', 's'); // global_data_tables.cpp
const int kManifestTagTbar = IMPERIALISM_FOURCC('t', 'b', 'a', 'r'); // global_data_tables.cpp
const int kManifestTagTclr = IMPERIALISM_FOURCC('t', 'c', 'l', 'r'); // global_data_tables.cpp
const int kManifestTagTech = IMPERIALISM_FOURCC('t', 'e', 'c', 'h'); // global_data_tables.cpp
const int kManifestTagTimb =
    IMPERIALISM_FOURCC('t', 'i', 'm', 'b'); // global_data_tables.cpp; 6 Mac screen(s)
const int kControlTagTrat =
    IMPERIALISM_FOURCC('t', 'r', 'a', 't'); // diplomacy-map "trade" button hover-text variant
const int kControlTagTrtt =
    IMPERIALISM_FOURCC('t', 'r', 't', 't'); // diplomacy-map "treaty" button hover-text variant
const int kControlTagTrty =
    IMPERIALISM_FOURCC('t', 'r', 't', 'y'); // diplomacy-map "treaty" action button
const int kManifestTagTyer = IMPERIALISM_FOURCC('t', 'y', 'e', 'r'); // global_data_tables.cpp
const int kManifestTagWare = IMPERIALISM_FOURCC('w', 'a', 'r', 'e'); // global_data_tables.cpp
const int kManifestTagWool =
    IMPERIALISM_FOURCC('w', 'o', 'o', 'l'); // global_data_tables.cpp; 5 Mac screen(s)
