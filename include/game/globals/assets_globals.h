#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/assets/timer_slots.h"

extern TAssetMgr* g_pAssetMgr;

// CD-audio MCI device singleton (see game/TCdAudioDevice.h).
extern TCdAudioDevice g_cdAudioDevice; // 0x006a60bc

// Audio timer-slot registry (see game/timer_slots.h): 10 callbacks + 10 live timer ids.
extern TimerSlotCallback g_timerSlotCallbacks[10]; // 0x006a5cf8

extern UINT g_timerSlotIds[10]; // 0x006a5c98

extern int g_timerDispatchSuppressAssert; // 0x006a5d24

extern char g_szSavedDocumentMarker_0069B848[];

extern char g_szLoadedDocumentMarker_0069B854[];

extern char s_Data_scores_dat_0069b7fc[];

extern "C" {
extern int g_nAuxOutputDeviceIndex;

} // extern "C"
