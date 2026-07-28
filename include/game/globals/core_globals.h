#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern "C" int g_nStartupAutoResolutionMode;

// Private retail assert guards for TStream's McAppStream.cpp diagnostics.
extern int g_streamLine304AssertGuard;

extern int g_streamLine596AssertGuard;

// Application save-flow names and writable scenario buffer.
extern char g_szImpSaveExtension_00698708[];
extern char g_szMultiplayerSavePrefix_00698710[];
extern char g_szSingleSlotSavePrefix_00698718[];
extern char g_ScenarioSaveNameBuffer_006A2178[0x30];
