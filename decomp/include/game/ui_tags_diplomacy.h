#pragma once

#include "game/ui_fourcc.h"

// Four-character tags diplomacy and nation screens.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kControlTagCan0 = IMPERIALISM_FOURCC(
    'c', 'a', 'n', '0'); // TCouncilView.cpp, TNominationView.cpp; 2 Mac screen(s)
const int kControlTagCan1 = IMPERIALISM_FOURCC(
    'c', 'a', 'n', '1'); // TCouncilView.cpp, TNominationView.cpp; 2 Mac screen(s)
const int kControlTagCann =
    IMPERIALISM_FOURCC('c', 'a', 'n', 'n'); // defense-minister "cannon"/war-declaration button
const int kControlTagCoa0 =
    IMPERIALISM_FOURCC('c', 'o', 'a', '0'); // TCouncilView.cpp; 1 Mac screen(s)
const int kControlTagCoa1 =
    IMPERIALISM_FOURCC('c', 'o', 'a', '1'); // TCouncilView.cpp; 1 Mac screen(s)
const int kControlTagDisp =
    IMPERIALISM_FOURCC('d', 'i', 's', 'p'); // minister-view display/help sub-picture
const int kControlTagDoc0 =
    IMPERIALISM_FOURCC('d', 'o', 'c', '0'); // TGrantsView.cpp; 1 Mac screen(s)
const int kControlTagDocs =
    IMPERIALISM_FOURCC('d', 'o', 'c', 's'); // TGrantsView.cpp; 1 Mac screen(s)
const int kControlTagExpo =
    IMPERIALISM_FOURCC('e', 'x', 'p', 'o'); // foreign-minister "export" button
const int kControlTagLink =
    IMPERIALISM_FOURCC('l', 'i', 'n', 'k'); // TTradePanelView.cpp; 1 Mac screen(s)
const int kControlTagLtab =
    IMPERIALISM_FOURCC('l', 't', 'a', 'b'); // action-topic selection bracket (left)
const int kControlTagMkey =
    IMPERIALISM_FOURCC('m', 'k', 'e', 'y'); // TInfoPanelView.cpp; 1 Mac screen(s)
const int kControlTagOvr0 =
    IMPERIALISM_FOURCC('o', 'v', 'r', '0'); // TInfoPanelView.cpp; 1 Mac screen(s)
const int kControlTagProp = IMPERIALISM_FOURCC('p', 'r', 'o', 'p'); // offer-desk proposal text
const int kControlTagRtab =
    IMPERIALISM_FOURCC('r', 't', 'a', 'b'); // action-topic selection bracket (right)
const int kControlTagScr0 =
    IMPERIALISM_FOURCC('s', 'c', 'r', '0'); // first of 7 sequential score-row labels (scr0-scr6)
const int kControlTagScr5 =
    IMPERIALISM_FOURCC('s', 'c', 'r', '5'); // TTreatiesView.cpp; 1 Mac screen(s)
const int kControlTagTraa =
    IMPERIALISM_FOURCC('t', 'r', 'a', 'a'); // TTradePanelView.cpp; 1 Mac screen(s)
