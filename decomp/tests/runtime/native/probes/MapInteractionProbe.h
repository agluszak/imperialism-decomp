#pragma once

#ifndef IMPERIALISM_MAP_INTERACTION_PROBE_H
#define IMPERIALISM_MAP_INTERACTION_PROBE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error MapInteractionProbe is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

class TMapDialog;

// Native pointer movement over the map.
//
// This is deliberately narrow, and it is the one place in the suite allowed to synthesise a
// Win32 input message. `runtime-source-policy-gate` rejects coordinate automation because a
// test that drives the game by clicking at (312, 118) asserts nothing about the game -- it
// asserts about a layout. Hovering is different: the cursor a tile classifies to *is* the
// behaviour under test, and there is no control-activation path that produces a hover at all.
//
// So the rule this keeps is: a point is always derived from the map's own projection of a tile
// index, never written as a literal, and the caller says which tile it means. Scenario bodies
// call these; they do not call SendMessage.
namespace MapInteractionProbe {

// Move the pointer to a point in the map dialog's own coordinates, converting to host window
// coordinates on the way. `localPoint` comes from the map's tile projection.
//
// Clears the dialog's cached region band first: the cursor classifier short-circuits when the
// pointer is still inside the band it last resolved, so a hover into the same band would be
// dropped and the test would read the previous cursor.
bool HoverAtLocalPoint(TMapDialog* mapDialog, const CPoint& localPoint);

// Two hovers in sequence, for the "moving the pointer redraws what it left behind" check.
bool HoverAcrossLocalPoints(TMapDialog* mapDialog, const CPoint& firstLocalPoint,
                            const CPoint& secondLocalPoint);

} // namespace MapInteractionProbe

#endif
