#pragma once
#include "game/globals/global_types.h"

extern "C" int g_nStartupAutoResolutionMode;
extern "C" ImperialismApp* g_pImperialismApp;
extern "C" int g_nSaveFormatVersion;
extern "C" BOOL g_cachedShowSplashFlag;
extern "C" const char* const g_pRegistryCompanyKey;
extern "C" const char* const g_pRegistryAppKey;
extern "C" const char* const g_pRegistryProfileAppName;
extern "C" const char* const g_pRegistrySettingsSection;
extern "C" const char* const g_pRegistrySettingsSectionAlt;
extern "C" const char* const g_pRegistryAutoResKey;
extern "C" const char* const g_pRegistryLanguageKey;

// Private retail assert guards for TStream's McAppStream.cpp diagnostics.
extern int g_streamLine304AssertGuard;

extern int g_streamLine596AssertGuard;

// Application save-flow names and writable scenario buffer.
extern char g_szImpSaveExtension[];
extern char g_szMultiplayerSavePrefix[];
extern char g_szSingleSlotSavePrefix[];
extern char g_ScenarioSaveNameBuffer[48];
