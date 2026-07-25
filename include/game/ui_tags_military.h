#pragma once

#include "game/ui_fourcc.h"

// Four-character tags military, navy, and tactical screens.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kControlTagNeXT =
    IMPERIALISM_FOURCC('N', 'e', 'X', 'T'); // TDiplomacyMgr.cpp, TNextDiplomationCommand.cpp
const int kControlTagAttackerCoat =
    IMPERIALISM_FOURCC('a', 'c', 'o', 'a'); // TTacticalHolaPicture.cpp; 1 Mac screen(s)
const int kControlTagArro =
    IMPERIALISM_FOURCC('a', 'r', 'r', 'o'); // ship-fraction arrow/theme label
const int kControlTagBomb = IMPERIALISM_FOURCC('b', 'o', 'm', 'b'); // bombard hotspot
const int kControlTagButl = IMPERIALISM_FOURCC('b', 'u', 't', 'l'); // TGameInfoPicture.cpp
const int kControlTagButm = IMPERIALISM_FOURCC('b', 'u', 't', 'm'); // TGameInfoPicture.cpp
const int kControlTagButn = IMPERIALISM_FOURCC('b', 'u', 't', 'n'); // TGameInfoPicture.cpp
const int kControlTagCrew = IMPERIALISM_FOURCC('c', 'r', 'e', 'w'); // navy ship crew display mode
const int kControlTagCurr =
    IMPERIALISM_FOURCC('c', 'u', 'r', 'r'); // tactical current-unit portrait
const int kControlTagDefenderCoat =
    IMPERIALISM_FOURCC('d', 'c', 'o', 'a'); // TTacticalHolaPicture.cpp; 1 Mac screen(s)
const int kControlTagDepl =
    IMPERIALISM_FOURCC('d', 'e', 'p', 'l'); // TMultiplayerMgr.cpp, TTacticalBattle.cpp
const int kControlTagDigg =
    IMPERIALISM_FOURCC('d', 'i', 'g', 'g'); // TMultiplayerMgr.cpp, TTacticalBattle.cpp
const int kControlTagDumy = IMPERIALISM_FOURCC('d', 'u', 'm', 'y'); // TInfoBarBehavior.cpp
const int kControlTagEadm =
    IMPERIALISM_FOURCC('e', 'a', 'd', 'm'); // TBattleReportView.cpp; 1 Mac screen(s)
const int kControlTagEflg =
    IMPERIALISM_FOURCC('e', 'f', 'l', 'g'); // TBattleReportView.cpp; 1 Mac screen(s)
const int kControlTagEshp =
    IMPERIALISM_FOURCC('e', 's', 'h', 'p'); // TBattleReportView.cpp; 1 Mac screen(s)
const int kControlTagFadm =
    IMPERIALISM_FOURCC('f', 'a', 'd', 'm'); // TBattleReportView.cpp; 1 Mac screen(s)
const int kControlTagFflg =
    IMPERIALISM_FOURCC('f', 'f', 'l', 'g'); // TBattleReportView.cpp; 1 Mac screen(s)
const int kControlTagFire =
    IMPERIALISM_FOURCC('f', 'i', 'r', 'e'); // TMultiplayerMgr.cpp, TTacticalBattle.cpp
const int kControlTagFshp =
    IMPERIALISM_FOURCC('f', 's', 'h', 'p'); // TBattleReportView.cpp; 1 Mac screen(s)
const int kControlTagFlgL =
    IMPERIALISM_FOURCC('f', 'l', 'g', 'L'); // detailed battle report left flag
const int kControlTagFlgR =
    IMPERIALISM_FOURCC('f', 'l', 'g', 'R'); // detailed battle report right flag
const int kControlTagGowy =
    IMPERIALISM_FOURCC('g', 'o', 'w', 'y'); // flag-options "go/continue" hotspot
const int kControlTagHdr0 = IMPERIALISM_FOURCC(
    'h', 'd', 'r', '0'); // first of 5 sequential game-info header labels (hdr0-hdr4)
const int kControlTagHelp = IMPERIALISM_FOURCC('h', 'e', 'l', 'p'); // tactical toolbar help button
const int kControlTagHull = IMPERIALISM_FOURCC('h', 'u', 'l', 'l'); // navy ship hull display mode
const int kControlTagInfB = IMPERIALISM_FOURCC('i', 'n', 'f', 'B'); // TInfoBarBehavior.cpp
const int kControlTagLose =
    IMPERIALISM_FOURCC('l', 'o', 's', 'e'); // TClientGreatPower.cpp, TMultiplayerMgr.cpp
const int kControlTagMine =
    IMPERIALISM_FOURCC('m', 'i', 'n', 'e'); // TMultiplayerMgr.cpp, TTacticalBattle.cpp
const int kControlTagNatL =
    IMPERIALISM_FOURCC('n', 'a', 't', 'L'); // detailed battle report left nation label
const int kControlTagNatR =
    IMPERIALISM_FOURCC('n', 'a', 't', 'R'); // detailed battle report right nation label
const int kControlTagMusi = IMPERIALISM_FOURCC('m', 'u', 's', 'i'); // music-volume scrollbar
const int kControlTagNavy =
    IMPERIALISM_FOURCC('n', 'a', 'v', 'y'); // TBatRepDetLine.cpp, TNavyMgr.cpp; 1 Mac screen(s)
const int kControlTagOpca = IMPERIALISM_FOURCC('o', 'p', 'c', 'a'); // auto-resolution-mode checkbox
const int kControlTagOpta = IMPERIALISM_FOURCC(
    'o', 'p', 't', 'a'); // first of 26 sequential game-preferences checkboxes (opta-opt+0x19)
const int kControlTagNooo =
    IMPERIALISM_FOURCC('n', 'o', 'o', 'o'); // auto-resolution "No" radio option
const int kControlTagPurc = IMPERIALISM_FOURCC('p', 'u', 'r', 'c'); // tech-item purchase button
const int kControlTagTpca =
    IMPERIALISM_FOURCC('t', 'p', 'c', 'a'); // auto-resolution prompt text (game preferences)
const int kControlTagRaly =
    IMPERIALISM_FOURCC('r', 'a', 'l', 'y'); // TMultiplayerMgr.cpp, TTacticalBattle.cpp
const int kControlTagResu =
    IMPERIALISM_FOURCC('r', 'e', 's', 'u'); // TBattleReportView.cpp; 2 Mac screen(s)
const int kControlTagRupt =
    IMPERIALISM_FOURCC('r', 'u', 'p', 't'); // TBatRepDetLine.cpp, TNavyMgr.cpp
const int kControlTagSail = IMPERIALISM_FOURCC('s', 'a', 'i', 'l'); // navy ship sail display mode
const int kControlTagScvw = IMPERIALISM_FOURCC('s', 'c', 'v', 'w'); // scroll view
const int kControlTagSkip =
    IMPERIALISM_FOURCC('s', 'k', 'i', 'p'); // TTacticalBattle.cpp, TTacticalBattleView.cpp
const int kControlTagSoun =
    IMPERIALISM_FOURCC('s', 'o', 'u', 'n'); // sound-effects-volume scrollbar
const int kControlTagTpic = IMPERIALISM_FOURCC('t', 'p', 'i', 'c'); // tactical target-unit portrait
const int kControlTagTxt0 =
    IMPERIALISM_FOURCC('t', 'x', 't', '0'); // first of 8 sequential option text lines (txt0-txt7)
const int kControlTagTxta = IMPERIALISM_FOURCC(
    't', 'x', 't', 'a'); // first of 14 sequential game-info text lines (txta-txtn)
const int kControlTagYess =
    IMPERIALISM_FOURCC('y', 'e', 's', 's'); // TGamePreferencesPicture.cpp; 1 Mac screen(s)
