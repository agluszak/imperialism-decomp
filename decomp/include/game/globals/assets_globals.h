#pragma once
#include "game/globals/global_types.h"
#include "game/assets/timer_slots.h"

extern TAssetMgr* g_pAssetMgr;
extern TSoundResourceManager g_soundResourceManager;
extern short g_randomAudioCuePollCounter;
extern TSoundPlayer* g_pSfxPlaybackSystem;
extern int g_localizationAudioSlotCursor;

// CD-audio MCI device singleton (see game/TCdAudioDevice.h).
extern TCdAudioDevice g_cdAudioDevice;

// Audio timer-slot registry (see game/timer_slots.h): 10 callbacks + 10 live timer ids.
extern TimerSlotCallback g_timerSlotCallbacks[10];

extern UINT g_timerSlotIds[10];

extern int g_timerDispatchSuppressAssert;

extern char g_szSavedDocumentMarker[];

extern char g_szLoadedDocumentMarker[];

extern char s_Data_scores_dat[];

extern "C" {
extern int g_nAuxOutputDeviceIndex;

} // extern "C"
