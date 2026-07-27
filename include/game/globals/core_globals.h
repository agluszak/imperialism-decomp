#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/prelude.h"

extern "C" int g_nStartupAutoResolutionMode;

// Private retail assert guards for TStream's McAppStream.cpp diagnostics.
extern int g_streamLine304AssertGuard;

extern int g_streamLine596AssertGuard;
