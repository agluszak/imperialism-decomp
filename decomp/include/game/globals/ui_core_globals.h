#pragma once
#include "game/globals/global_types.h"
#include "game/core/TMouseCaptureState.h"
#include <afxtempl.h>

class TAnimator;
class TMacViewMgr;
class TView;
class TViewMgr;

int SetGlobalUiInvalidationFlagAndReturnPrevious(int newValue);
int ClearGlobalUiInvalidationFlagAndReturnPrevious();
int GetMcAppUiActiveFlag();

extern TView* g_pUiResourceContext;

extern POINT g_ptNationComparisonModalMessage; // @ 0x6a3180

extern POINT g_ptUiPromptModalMessage; // @ 0x6a5be0

extern POINT g_ptCitySiteSelectionDialogPlacement; // @ 0x6a5b58

extern int g_nationInfoGoldResourceOverride;
extern int g_nViewMgrModalAssertGate; // @ 0x6a5bb0

extern int g_lastTurnAlertTick;

extern CPoint g_turnEventDialogAnchorPoint;

// UI runtime managers and resource-tree state.
extern CPoint g_ptUiAnimatorSurfaceBounds;
extern bool g_bStrategicMapSelectionOverlayPhase;
extern TMacViewMgr* g_pMacViewMgr;
extern TViewMgr* g_pViewMgr;
extern TAnimator* g_pUiAnimator;
extern TView* g_pUiResourceHead;
extern TInfoBarText* g_pCursorControlPanel;
extern TLanguageMgr* g_pLanguageMgr;
extern TApplication* g_pApplication;
extern TTurnEventDialogFactoryRegistry* g_pTurnEventDialogFactoryRegistry;
extern CList<TView*, TView*> g_UiWidgetBuildStack;

extern "C" void* g_pScopedMapQuickDrawViewContext;
extern "C" CDC* g_pScopedMapQuickDrawDcHandleObject;

extern char s_szTurnHistoryPrefix[];

extern "C" {
extern const unsigned int g_strategicMapStatusIconTagTable[18];

extern int g_Reset_Quick_Draw_Value_0064B8F0;

extern int g_Reset_Quick_Draw_Value_0064B8F4;

extern const short g_Reset_Quick_Draw_WordState;

extern short g_Reset_Quick_Draw_State;

extern int g_nQuickDrawPenHorizontalSize;

extern int g_nQuickDrawPenVerticalSize;

extern int g_bQuickDrawStrokePairDirty;

extern CFont* g_pQuickDrawCachedUiFont;

extern TextStyle g_QuickDrawCachedFontPreset;

extern bool g_bQuickDrawCachedFontDirty;

extern const char* const g_apszQuickDrawFontFaceNames[5];

extern CFont* g_pQuickDrawCachedMeasureFont; // 0x6a1d48

extern TextStyle g_QuickDrawMeasureFontPreset; // 0x6a1d4c

extern bool g_bQuickDrawMeasureFontDirty; // 0x6a1d56

extern COLORREF g_QuickDrawBackgroundColor;

extern int g_nQuickDrawResolvedTextOriginX;

extern int g_nQuickDrawResolvedTextOriginY;

extern HGDIOBJ g_hQuickDrawSavedBitmap;

extern int g_nActiveQuickDrawSurfaceFlags;

extern int g_QuickDrawRegionBoundsAssertGate;

extern int g_QuickDrawSetCursorAssertGate;

extern int g_QuickDrawGetCursorAssertGate;

extern int g_QuickDrawEqualRgnAssertGate;

extern int g_QuickDrawStateAssertGate;

extern char* g_pNationInfoEmptyText;

extern short g_anAbilityStatusPictureIndex[29];

extern short g_overlaySfxSeasonWord;

extern int g_McAppUiActiveFlag;

extern int g_McAppUiDrawGate;

// Gate checked before the invalidation-flag assert/log call in the child-detach path.
extern int g_McAppUiFlag_006A1AE0;

// Gate checked before the UI resource-entry allocation assert in TEventHandler slot 0x08.
extern int g_McAppUiFlag_006A1AE4;

// Further invalidation-flag assert gates (McAppUI.cpp lines 1914 / 1922).
extern int g_McAppUiFlag_006A1AFC;

extern int g_McAppUiFlag_006A1B00;

// Per-line one-shot invalidation-flag assert gates used by TWindow's UI slot bodies.
extern int g_McAppUiFlag_006A1B04;

extern int g_McAppUiFlag_006A1B08;

extern int g_McAppUiFlag_006A1B10;

extern int g_McAppUiFlag_006A1B14;

extern int g_McAppUiFlag_006A1B18;

extern int g_McAppUiFlag_006A1B1C;
// One-shot assert gate read only by TCtlMgr's slot-0x71 default (0x492db0).
extern int g_McAppUiFlag_006A1B5C;

extern int g_McAppUiFlag_006A1B0C;

// Reentrancy guard for the root UpdateWindow pass driven by TView slot 0x4f.
extern int g_McAppUiUpdateWindowRecursionGuard;

// Active QuickDraw origin/render context view for slot 0x3e.
extern class TView* g_McAppUiActiveRenderContext;

extern int g_McAppUiDefaultPosX;

extern int g_McAppUiDefaultPosY;

// Mouse-capture drag/repeat state used by TControl's input slots.
extern TMouseCaptureState g_McAppMouseCaptureState; // 0x6a1a68

extern unsigned int g_McAppUiMouseCaptureTimerId; // 0x6a1adc

extern char g_szMcAppUiSourcePath[];

extern char g_szQuickDrawSourcePath[];

extern char g_szMcWindowSourcePath[];

extern int g_nMcWindowStateMsgAssertGate;

extern char g_szIncludeViewSourcePath[];

extern char g_szAmbitCadreEgoutClassName[];
extern int g_AmbitCadreEgoutWndClassAtom;

extern int g_nIncludeViewAssertGate;
extern int g_nIncludeViewQueueAssertGate;
extern int g_nIncludeViewCaptureAssertGate;

// One-shot assert / init gates used by CIncludeView's main-pane reinitialise path.
extern int g_nIncludeViewReinitAssertGate;
extern int g_nIncludeViewReinitThreadOnceGate;
extern int g_nMcAppUiAssertGate;

extern int g_nIncludeViewPointerAssertGate;

extern char g_szMcAppUiHeaderPath[];

extern int g_McAppUiFlag_006A143C;

extern "C" const char s_SourcePathUViewMgr[];

extern "C" const char s_SourcePathUViewMgrMore[];

extern "C" const char s_SourcePathUHelpMgr[];

extern "C" const char s_SourcePathUMacViewMgr[];

extern const char* const g_pszEmptyTextPointer; // = g_szEmptyString @ 0x656f60

extern TextStyle g_UiResourceEntryDefaultTextStyle;

extern "C" const char s_TurnEventCursorNameFormat[];

extern "C" short g_anStrategicMapOverlaySourceRowByIconId[28];

// THelpMgr.cpp — periodic nation-comparison advisory tick.
extern short g_nTurnFlowNationComparisonAdvisoryTick;

} // extern "C"
