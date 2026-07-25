#pragma once

#include "game/ui_fourcc.h"

// Four-character tags strategic map screens.
//
// Declared through IMPERIALISM_FOURCC so the characters ARE the value; see
// include/game/ui_fourcc.h for the encoding policy. A tag lives here when the
// manual source that uses it belongs to this subsystem only; tags crossing
// subsystems live in ui_tags_common.h.

const int kControlTagZmIn = IMPERIALISM_FOURCC('Z', 'm', 'I', 'n'); // map zoom-in hotspot
const int kControlTagZmOt = IMPERIALISM_FOURCC('Z', 'm', 'O', 't'); // map zoom-out hotspot
const int kControlTagAdam =
    IMPERIALISM_FOURCC('a', 'd', 'a', 'm'); // TMapUberPicture.cpp; 3 Mac screen(s)
const int kControlTagAgr1 =
    IMPERIALISM_FOURCC('a', 'g', 'r', '1'); // middle of 3 aggression-level buttons
const int kControlTagAgr2 =
    IMPERIALISM_FOURCC('a', 'g', 'r', '2'); // last of 3 aggression-level buttons
const int kControlTagAgro =
    IMPERIALISM_FOURCC('a', 'g', 'r', 'o'); // TMapUberPicture.cpp; 1 Mac screen(s)
const int kControlTagEcon = IMPERIALISM_FOURCC('e', 'c', 'o', 'n'); // map-editor economy panel
const int kControlTagGpee =
    IMPERIALISM_FOURCC('g', 'p', 'e', 'e'); // TMapUberPicture.cpp; 2 Mac screen(s)
const int kControlTagGene =
    IMPERIALISM_FOURCC('g', 'e', 'n', 'e'); // TArmyInfoView.cpp; Friendly army report
const int kControlTagLab1 =
    IMPERIALISM_FOURCC('l', 'a', 'b', '1'); // TMapUberPicture.cpp; 4 Mac screen(s)
const int kControlTagLab2 =
    IMPERIALISM_FOURCC('l', 'a', 'b', '2'); // TMapUberPicture.cpp; 5 Mac screen(s)
const int kControlTagLab3 =
    IMPERIALISM_FOURCC('l', 'a', 'b', '3'); // TMapUberPicture.cpp; 4 Mac screen(s)
const int kControlTagLab4 =
    IMPERIALISM_FOURCC('l', 'a', 'b', '4'); // TMapUberPicture.cpp; 1 Mac screen(s)
const int kControlTagNama =
    IMPERIALISM_FOURCC('n', 'a', 'm', 'a'); // TMapUberPicture.cpp; 1 Mac screen(s)
const int kControlTagOrds =
    IMPERIALISM_FOURCC('o', 'r', 'd', 's'); // TMapUberPicture.cpp; 2 Mac screen(s)
const int kControlTagOwne =
    IMPERIALISM_FOURCC('o', 'w', 'n', 'e'); // TMapUberPicture.cpp; 2 Mac screen(s)
const int kControlTagPrnu = IMPERIALISM_FOURCC('p', 'r', 'n', 'u'); // map-editor province number
const int kControlTagSend = IMPERIALISM_FOURCC('s', 'e', 'n', 'd'); // end-turn hotspot
const int kControlTagTown = IMPERIALISM_FOURCC(
    't', 'o', 'w',
    'n'); // TMapMgr.cpp, TMultiplayerMgr_HandleDiplomacyTurnEvent.cpp; 1 Mac screen(s)
const int kControlTagType =
    IMPERIALISM_FOURCC('t', 'y', 'p', 'e'); // selected map-editor place type
const int kControlTagUciv =
    IMPERIALISM_FOURCC('u', 'c', 'i', 'v'); // TMapUberPicture.cpp; 1 Mac screen(s)
const int kControlTagUnav =
    IMPERIALISM_FOURCC('u', 'n', 'a', 'v'); // TMapUberPicture.cpp; 1 Mac screen(s)
const int kControlTagWhom =
    IMPERIALISM_FOURCC('w', 'h', 'o', 'm'); // TMapUberPicture.cpp; 2 Mac screen(s)
