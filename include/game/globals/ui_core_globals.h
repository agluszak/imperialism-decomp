#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/global_types.h"
#include "game/core/TMouseCaptureState.h"

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

extern int g_nationInfoGoldResourceOverride_006a5bac;

extern int g_lastTurnAlertTick_006a31c0;

extern CPoint g_turnEventDialogAnchorPoint;

// UI runtime managers and resource-tree state.
extern CPoint g_ptUiAnimatorSurfaceBounds;
extern unsigned char g_bStrategicMapSelectionOverlayPhase;
extern TMacViewMgr* g_pMacViewMgr;
extern TViewMgr* g_pViewMgr;
extern TAnimator* g_pUiAnimator;
extern TView* g_pUiResourceHead;

extern char s_szTurnHistoryPrefix_0069b71c[];

extern "C" {
extern const unsigned int g_strategicMapStatusIconTagTable[18];

extern int g_Reset_Quick_Draw_Value_0064B8F0;

extern int g_Reset_Quick_Draw_Value_0064B8F4;

extern const short g_Reset_Quick_Draw_WordState_0064B8F8;

extern short g_Reset_Quick_Draw_State_006A1D10;

extern int g_nQuickDrawPenHorizontalSize;

extern int g_nQuickDrawPenVerticalSize;

extern int g_bQuickDrawStrokePairDirty;

extern CFont* g_pQuickDrawCachedUiFont;

extern TextStyle g_QuickDrawCachedFontPreset;

extern unsigned char g_bQuickDrawCachedFontDirty;

extern const char* const g_apszQuickDrawFontFaceNames[5];

// Measure-text cached font cluster (0x6a1d48-0x6a1d56): same shape as the draw-font
// cluster above. The preset's styleRef6 field IS the current text color (written by
// SetQuickDrawFillColor, read as COLORREF by the paint paths; the original PDB labels
// those 4 bytes g_uQuickDrawCurrentColor — it's the same field, not a separate global).
extern CFont* g_pQuickDrawCachedMeasureFont; // 0x6a1d48

extern TextStyle g_QuickDrawMeasureFontPreset; // 0x6a1d4c

extern unsigned char g_bQuickDrawMeasureFontDirty; // 0x6a1d56

extern COLORREF g_QuickDrawBackgroundColor;

extern int g_nQuickDrawResolvedTextOriginX;

extern int g_nQuickDrawResolvedTextOriginY;

extern HGDIOBJ g_hQuickDrawSavedBitmap;

extern int g_nActiveQuickDrawSurfaceFlags;

extern int g_QuickDrawRegionBoundsAssertGate;

extern int g_QuickDrawSetCursorAssertGate;

extern int g_QuickDrawGetCursorAssertGate;

extern int g_QuickDrawEqualRgnAssertGate;

extern char* g_pNationInfoEmptyText_0066f050;

extern short g_anAbilityStatusPictureIndex_0066F058[29];

extern short g_overlaySfxSeasonWord_0066f0a6;

// Gate checked before touching a control's native window (e.g. ValidateRect /
// InvalidateRect): non-zero once the UI subsystem/screen is realized.
extern int g_McAppUiActiveFlag_006950AC;

// Gate checked in the QuickDraw/GDI draw path before temporarily clearing the UI
// invalidation flag.
extern int g_McAppUiDrawGate_006A1AF8;

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

extern int g_McAppUiFlag_006A1B0C;

// Reentrancy guard for the root UpdateWindow pass driven by TView slot 0x4f.
extern int g_McAppUiUpdateWindowRecursionGuard_006A1AF0;

// Active QuickDraw origin/render context view for slot 0x3e.
extern class TView* g_McAppUiActiveRenderContext_006A1AF4;

// Default absolute layout position (x, y) used when a control has no owner context, in
// the position-propagation pass (TView::vmethod_0089).
extern int g_McAppUiDefaultPosX_006A1A60;

extern int g_McAppUiDefaultPosY_006A1A64;

// Mouse-capture drag/repeat state used by TControl's input slots.
extern TMouseCaptureState g_McAppMouseCaptureState; // 0x6a1a68

extern unsigned int g_McAppUiMouseCaptureTimerId_006A1ADC; // 0x6a1adc

// Source-file path string ("D:\\Ambit\\McAppUI.cpp") passed with a line number to the
// UI invalidation-flag assert/log helper.
extern char g_szMcAppUiSourcePath_006950B0[];

extern char g_szQuickDrawSourcePath_00695168[];

// Source-file path string ("D:\\Ambit\\McWindow.cpp") for CMcWindow's one-shot asserts,
// and the gate read before the unknown-wParam 0x468 assert fires.
extern char g_szMcWindowSourcePath_006950D8[];

extern int g_nMcWindowStateMsgAssertGate_006A1C74;

// Source-file path string ("D:\\Ambit\\IncludeView.cpp") for CIncludeView's one-shot
// asserts, and the gate read before the msg-0x4ef detach assert fires.
extern char g_szIncludeViewSourcePath_00694D10[];

extern int g_nIncludeViewAssertGate_006A17B0;
extern int g_nIncludeViewCaptureAssertGate_006A17B8;

// One-shot assert / init gates used by CIncludeView's main-pane reinitialise path.
extern int g_nIncludeViewReinitAssertGate_006A17BC;
extern int g_nIncludeViewReinitThreadOnceGate_006A17C0;
extern int g_nMcAppUiAssertGate_006A2480;

extern int g_nIncludeViewPointerAssertGate_006A17C4;

// Header path string ("D:\\Ambit\\McAppUI.h") passed with a line number to city-production
// dialog assert/log helpers on the TControl branch.
extern char g_szMcAppUiHeaderPath_006943CC[];

// Gate checked by TControl::AssertCityProductionGlobalStateInitialized before the
// McAppUI.h line-0x56f assert path runs.
extern int g_McAppUiFlag_006A143C;

extern "C" const char s_SourcePathUViewMgrMore_0069B740[];

extern "C" const char s_SourcePathUHelpMgr_00696C58[];

extern "C" const char s_SourcePathUMacViewMgr_00696D68[];

extern const char* const g_pszEmptyTextPointer_00656f60; // = g_szEmptyString @ 0x656f60

// TControl.cpp — UI resource entry default text-style/command-param block (also
// TMyStaticText.cpp/TStaticText.cpp).
extern TextStyle g_UiResourceEntryDefaultTextStyle;

extern "C" const char s_TurnEventCursorNameFormat_0069B6B4[];

// TMacViewMgr.cpp — source-row offsets into the strategic unit-overlay atlas.
// Negative entries are unsupported icon identifiers. 0x696d20.
extern "C" short g_anStrategicMapOverlaySourceRowByIconId[28];

// THelpMgr.cpp — periodic nation-comparison advisory tick.
extern short g_nTurnFlowNationComparisonAdvisoryTick;

} // extern "C"
