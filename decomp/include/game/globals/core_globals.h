#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"

extern "C" int g_nStartupAutoResolutionMode;
extern "C" ImperialismApp* g_pImperialismApp;
extern "C" int g_nSaveFormatVersion;
extern "C" BOOL g_cachedShowSplashFlag;
extern "C" const char* const g_pRegistryCompanyKey_0063E038;
extern "C" const char* const g_pRegistryAppKey_0063E03C;
extern "C" const char* const g_pRegistryProfileAppName_0063E050;
extern "C" const char* const g_pRegistrySettingsSection_0063E040;
extern "C" const char* const g_pRegistrySettingsSectionAlt_0063E044;
extern "C" const char* const g_pRegistryAutoResKey_0063E048;
extern "C" const char* const g_pRegistryLanguageKey_0063E04C;

// Private retail assert guards for TStream's McAppStream.cpp diagnostics.
extern int g_streamLine304AssertGuard;

extern int g_streamLine596AssertGuard;

// Application save-flow names and writable scenario buffer.
extern char g_szImpSaveExtension_00698708[];
extern char g_szMultiplayerSavePrefix_00698710[];
extern char g_szSingleSlotSavePrefix_00698718[];
extern char g_ScenarioSaveNameBuffer_006A2178[0x30];
