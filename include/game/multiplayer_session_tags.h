#pragma once

#include "game/ui_fourcc.h"

// Four-character tags multiplayer session and network message tags.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kSessionTagAced =
    IMPERIALISM_FOURCC('a', 'c', 'e', 'd'); // TLoungeDialog.cpp, TMultiplayerMgr.cpp
const int kSessionTagAwol = IMPERIALISM_FOURCC('a', 'w', 'o', 'l'); // TMultiplayerMgr.cpp
const int kSessionTagBox0 =
    IMPERIALISM_FOURCC('b', 'o', 'x', '0'); // TMultiMessagePicture.cpp; 1 Mac screen(s)
const int kSessionTagBusy =
    IMPERIALISM_FOURCC('b', 'u', 's', 'y'); // TLoungeDialog.cpp, TMultiplayerMgr.cpp
const int kSessionTagBxb0 = IMPERIALISM_FOURCC('b', 'x', 'b', '0'); // TMultiplayerMgr.cpp
const int kSessionTagCgop = IMPERIALISM_FOURCC('c', 'g', 'o', 'p'); // TMultiplayerMgr.cpp
const int kSessionTagDead =
    IMPERIALISM_FOURCC('d', 'e', 'a', 'd'); // TMultiplayerMgr.cpp; 1 Mac screen(s)
const int kSessionTagDeca = IMPERIALISM_FOURCC('d', 'e', 'c', 'a'); // TMultiplayerMgr.cpp
const int kSessionTagDehu =
    IMPERIALISM_FOURCC('d', 'e', 'h', 'u'); // TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp
const int kSessionTagFoff = IMPERIALISM_FOURCC('f', 'o', 'f', 'f'); // TMultiplayerMgr.cpp
const int kSessionTagGoin = IMPERIALISM_FOURCC('g', 'o', 'i', 'n'); // TMultiplayerMgr.cpp
const int kSessionTagInit = IMPERIALISM_FOURCC('i', 'n', 'i', 't'); // TMultiplayerMgr.cpp
const int kSessionTagJedi =
    IMPERIALISM_FOURCC('j', 'e', 'd', 'i'); // TLoungeDialog.cpp; 1 Mac screen(s)
const int kSessionTagLabl =
    IMPERIALISM_FOURCC('l', 'a', 'b', 'l'); // TLoungeDialog.cpp; 3 Mac screen(s)
const int kSessionTagMesg =
    IMPERIALISM_FOURCC('m', 'e', 's', 'g'); // TMultiMessagePicture.cpp; 1 Mac screen(s)
const int kSessionTagMess = IMPERIALISM_FOURCC(
    'm', 'e', 's', 's'); // TLoungeDialog.cpp, TMultiplayerMgr.cpp; 1 Mac screen(s)
const int kSessionTagNetX = IMPERIALISM_FOURCC('n', 'e', 't', 'X'); // TMultiplayerMgr.cpp
const int kControlTagPass = IMPERIALISM_FOURCC('p', 'a', 's', 's'); // password edit field
const int kSessionTagPik0 =
    IMPERIALISM_FOURCC('p', 'i', 'k', '0'); // TLoungeDialog.cpp; 1 Mac screen(s)
const int kSessionTagPik6 =
    IMPERIALISM_FOURCC('p', 'i', 'k', '6'); // TLoungeDialog.cpp; 1 Mac screen(s)
const int kSessionTagPose =
    IMPERIALISM_FOURCC('p', 'o', 's', 'e'); // TMultiplayerMgr.cpp, TPoseMessageDialog.cpp
const int kSessionTagPrep = IMPERIALISM_FOURCC('p', 'r', 'e', 'p'); // TMultiplayerMgr.cpp
const int kControlTagPro0 = IMPERIALISM_FOURCC('p', 'r', 'o', '0'); // default protocol option tag
const int kSessionTagRad0 =
    IMPERIALISM_FOURCC('r', 'a', 'd', '0'); // TLoungeDialog.cpp; 2 Mac screen(s)
const int kSessionTagRad6 =
    IMPERIALISM_FOURCC('r', 'a', 'd', '6'); // TLoungeDialog.cpp; 1 Mac screen(s)
const int kSessionTagRedy = IMPERIALISM_FOURCC(
    'r', 'e', 'd', 'y'); // TMultiplayerMgr.cpp, TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp
const int kSessionTagRsvp = IMPERIALISM_FOURCC('r', 's', 'v', 'p'); // TMultiplayerMgr.cpp
const int kSessionTagScz9 = IMPERIALISM_FOURCC('s', 'c', 'z', '9'); // TMultiplayerMgr.cpp
const int kControlTagTgam =
    IMPERIALISM_FOURCC('t', 'g', 'a', 'm'); // join-selector target-game label
const int kSessionTagTras = IMPERIALISM_FOURCC('t', 'r', 'a', 's'); // TMultiplayerMgr.cpp
const int kSessionTagUhed = IMPERIALISM_FOURCC('u', 'h', 'e', 'd'); // TMultiplayerMgr.cpp
const int kSessionTagUnas = IMPERIALISM_FOURCC(
    'u', 'n', 'a', 's'); // TMultiplayerMgr.cpp, TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp
const int kSessionTagUnkn = IMPERIALISM_FOURCC(
    'u', 'n', 'k', 'n'); // TMultiplayerMgr.cpp, TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp
