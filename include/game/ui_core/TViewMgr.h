#pragma once

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"
#include "game/quickdraw_types.h"
#include "game/turn_event_codes.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TTown;
struct TCombatReportContext;
class TToolBarClusterVtbl;
class TView;
class TEventHandler;
class TControl;
class TDiplomacyMapView;
class TMovieView;
class TTaskForce;
class TNavyRoster;

// VTABLE: IMPERIALISM 0x0066f120
class TViewMgr : public TObject {
public:
  // Base Windows cursor resource ID for turnEventCursors' indexing scheme (see below).
  enum { kCursorResourceIdBase = 1000 };

  DECLARE_DYNCREATE(TViewMgr)
  virtual ~TViewMgr() override;                    // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5d5250
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5d5200
  virtual void Free() override;                    // slot 0x07 0x5d51e0
  virtual void LoadTurnEventCursorTable();         // slot 0x0a 0x5d5100
  virtual void MakeGameSetupDialog();              // slot 0x0b 0x5dcaa0
  virtual void SetBackColor(short colorCode);      // slot 0x0c 0x5d5780
  virtual void SetForeColor(short colorCode);      // slot 0x0d 0x5d5750
  virtual int ClassifyTurnStateForOverlayMode();   // slot 0x0e 0x5d5960
  virtual void BuildAndShowTurnOverlayByMode(int overlayMode, int contextArg); // slot 0x0f 0x5d6480
  virtual void HandleTurnEventVtableSlot40RefreshGoldDialog();                 // slot 0x10 0x5d57b0
  virtual void ComputeTurnEventDialogPlacementByCode(TView* dialogView,
                                                     POINT* outPlacement); // slot 0x11 0x5d69b0
  virtual void RefreshMainViewNationIndicatorForCurrentTurnEvent();        // slot 0x12 0x5d6b70

  // Extended UI-runtime virtuals (same object as g_pUiRuntimeContext @ 0x006A21BC).
  virtual void DispatchTurnEvent(TurnEventCodeStorage eventCode, int payload); // 0x4c
  virtual void SetCursorRangeAndRefreshMainPanel(int payload);                 // 0x50
  virtual short GetPendingTurnOverlayCode();                                   // 0x54
  virtual void RefreshStrategicMapStatusIconsForActiveNation();                // 0x58
  virtual void RefreshTradeAndIndustryOverviewScreen(int nationIndex);         // 0x5c
  // Resolves the active dialog's 'main' and 'curs' panels, refreshes the cursor info
  // panel's map-hint style, then clears the 'main' panel's title text (0x5da040).
  virtual void RefreshMainDialogAndCursorHelp(int eventCode); // 0x60
  // Sibling of slot 0x60: refreshes the 'curs' cursor panel, then repopulates the
  // 'quer' query label and 'titL' nation-title panel from the current scenario setup
  // (0x5da180).
  virtual void HandleTurnEvent2260_RefreshMainHudTitles(int eventCode); // 0x64

  // UI runtime helper functions
  virtual void AddPendingTurnOverlayCode(int modeValue);                   // 0x68
  virtual void HandleTurnEvent7D8_ActivateDiplomacyMapView(int eventCode); // 0x6c
  // Resolve the factory dialog for eventCode, commit its 'GOLD' child, then push the
  // slot-0x9c refresh down the dialog's linked children (0x5d6cd0).
  virtual void HandleTurnEventDialogFactorySlot70(int eventCode); // 0x70 0x5d6cd0
  // Slots 0x74/0x78/0x7C/0x80 share the same body: resolve the factory dialog for
  // eventCode, commit its 'GOLD' child, then show/refresh/free the dialog node.
  virtual void HandleTurnEventDialogFactorySlot74(int eventCode); // 0x74 0x5d6d70
  virtual void HandleTurnEventDialogFactorySlot78(int eventCode); // 0x78 0x5d6e50
  virtual void HandleTurnEventDialogFactorySlot7C(int eventCode); // 0x7c 0x5d6f10
  virtual void HandleTurnEventDialogFactorySlot80(int eventCode); // 0x80 0x5d6fd0
  virtual void HandleTurnEvent7DE_RefreshTradeDiplomacyCityTransportSummary(int eventCode); // 0x84
  virtual void ShowAbilityStatusReport(int abilityIndex); // 0x88 0x5d8980 (ret 4)
  virtual void NoOpTurnEventStateVtableSlot8C(int arg);   // 0x8c
  virtual char MakeDiplomacyOfferDialog(short sourceNation, short targetNation,
                                        short proposalCode); // 0x90
  virtual char PoseWarOfferIfTurnFlowReady(int sourceNation, int arg1, int arg2,
                                           int promptCode); // 0x94
  virtual void DispatchNationActionToMainControl(int sourceNation, int arg1, int arg2, int arg3,
                                                 int targetNation);                // 0x98
  virtual void HandleTurnEvent2103_RunNationStatusReportUpdate(int pageIndex = 0); // 0x9c
  virtual void SyncTacticalStatusPanelRegion();                                    // 0xa0
  virtual void DispatchTurnEvent3B8AndWaitForCompletion(int payload,
                                                        TEventHandler* waitTarget); // 0xa4
  virtual void HandleTurnEvent7DB_SelectCityAndRefreshView(int nationSlot);         // 0xa8
  // Forwards to g_pStrategicMapViewSystem's own vtable slot 0x5c/0x60/0x68/0x6c/
  // 0x70/0x74 (TMacViewMgr) -- verified via disassembly (0057db14-style pattern:
  // `mov ecx,[g_pStrategicMapViewSystem]; mov eax,[ecx]; jmp [eax+0xNN]`, no
  // wrapping logic). Real orig names embed the target slot's byte offset. bd
  // imperialism-decomp-kdm.
  virtual void RefreshCityProductionUi();                     // 0xac 0x5d7f70
  virtual void ClearActiveCityBuildingViewSlot(short param1); // 0xb0 0x5d7f90
  // Opens the New City dialog (event 0x3b9) and stuffs the pending town into its
  // TPlaceCityDialog 'DLOG' child.
  virtual char ShowNewCityDialog(TTown* town); // 0xb4 0x5dcdf0
  // Opens factory dialog 0x2405, seeds its 'GOLD' trade-summary child with the three
  // caller args, places/refreshes it, then forwards the refresh result to the child
  // (0x5dc430).
  // Opens the Generic-expander dialog (event 0x2405) and stuffs the building slot,
  // city and production view into its TBuildingExpansionView 'DLOG' child.
  virtual void ShowBuildingExpansionDialog(short buildingSlotId, class TCity* city,
                                           class TCityProductionView* productionView); // 0xb8
  virtual void HandleTurnEvent7DD_RefreshOrderStatusPanelsAndIcons(int eventCode);     // 0xbc
  virtual void ForwardBuildStrategicMapRenderAtlasesAndTileMaskCaches();   // 0xc0 0x5dc180
  virtual void RenderTurnEventPalettePreviewSurfaceAndProgress();          // 0xc4 0x5dc1c0
  virtual void RebuildMapTileNeighborHighlightPolygonsForAllTiles();       // 0xc8 0x5dc1a0
  virtual void RefreshActiveGoldControlAndUiRuntimeState();                // 0xcc 0x5dc160
  virtual void InitializeCitySiteSelectionScreenForNation(int nationSlot); // 0xd0
  virtual void NoOpTurnEventStateVtableSlotD4(int arg);                    // 0xd4
  // Resolves the active dialog's 'GOLD' panel, notifies it of the current turn-event
  // code, then resolves+shows+refreshes the 0x546 factory dialog's own 'GOLD' child
  // (0x5dcf20).
  // Opens the CombatReport 2 dialog (event 0x546) and stuffs the report context into
  // its TCombatReportView 'DLOG' child; the argument is that context, not an event code.
  virtual void ShowCombatReportDialog(TCombatReportContext* reportContext); // 0xd8 0x5dcf20
  virtual int ShowConstructionOptionsDialog(int dialogValue = 0);           // 0xdc
  virtual void HandleGlobalMapNationContextSelection(int nationSlot, int unused = 0); // 0xe0
  // Opens factory dialog 0x1c52, places it, and sets the 'GOLD'->'name' text from a
  // localized string code (0x5dd220).
  virtual void HandleTurnEventDialogFactorySlotE4(int stringCode);  // 0xe4
  virtual void HandleTurnEventDialogFactorySlotE8(void* selection); // 0xe8
  // Refreshes the 0xdac factory dialog's 'page' roster for a tile-selection map click
  // (0x5dd900); reached from TArmyToolbar's map-tile-selection handler.
  virtual void HandleTurnEventDialogFactorySlotEC(int mapSelection); // 0xec
  // Mac oracle: TViewMgr::MakeNavyRosterDialog(TTaskForce*). Resolves the 0x2506
  // Navy Roster's TNavyRoster page, populates it from the supplied task force, and
  // returns the page after the modal dialog closes (0x5dd340).
  virtual TNavyRoster* MakeNavyRosterDialog(TTaskForce* activeMapOrderEntry); // 0xf0
  virtual void HandleTurnEventDialogFactorySlotF4();                          // 0xf4
  virtual void HandleTurnEventDialogFactorySlotF8();                          // 0xf8
  virtual void NoOpTurnEventStateVtableSlotFC(); // 0xfc 0x5dbd10 -- real body is a bare `ret`
  // Turn-event 0x5DE: re-assert + refresh the 'main' view panel (sibling of the 0x5DF
  // handler; the original brackets the body with a scoped empty CString). 0x5dbd30.
  virtual void HandleTurnEvent5DE_RefreshMainView(); // 0x100 0x5dbd30
  // Turn-event 0x5DF path (see DispatchTurnEvent): re-asserts and refreshes
  // the main view's 'main' panel (0x5dbdd0).
  virtual void HandleTurnEvent5DF_RefreshMainView(); // 0x104
  virtual void RefreshMainViewForTurnEvent5DF();     // 0x108
  // Resolves the active dialog's 'GOLD' control and configures its value-cell grid
  // (0x14 x 0x14) via the control's slot-0x79 virtual (0x5dc3f0).
  virtual void ConfigureActiveDialogGoldValueGridForTurnEvent3C0(); // 0x10c 0x5dc3f0
  virtual void ShowUnitHistory(short nationSlot);                   // 0x110 0x5dc690

  void ApplyLegendSplitSlot34(int split) {
    SetForeColor(static_cast<short>(split));
  }
  void QueueTurnStatusPromptSlot3C(int promptIndex, int payload) {
    BuildAndShowTurnOverlayByMode(promptIndex, payload);
  }
  void RefreshViewSlot48() {
    RefreshMainViewNationIndicatorForCurrentTurnEvent();
  }

  // Mac CodeWarrior names/signatures identify this palette family as GetColor,
  // SetColor, SetForeColor, and SetBackColor. Windows listing supplies the
  // implementations and addresses.
  QuickDrawPaletteIndex GetColor(short colorCode);
  void SetColor(short colorCode, unsigned char foreground);

  // 0x5ddd20 — opens the civilian ledger (TSuperCivRoster) inside factory dialog
  // 0xdac, runs it modally via the show/refresh chain, then applies the selected
  // civilian as the active map selection.
  void ShowCivilianLedgerDialogAndSelectUnit();
  // 0x5dda30 — army-roster sibling of the civilian ledger: replace the factory page with
  // TSuperArmyRoster, then activate and center the selected province.
  void ShowArmyRosterDialogAndActivateProvinceSelection();
  // 0x5dd450 — replace the Navy Roster factory page with TSuperNavyRoster and apply the
  // selected loose-zone or existing-task-force map context.
  void ShowNavyRosterDialogAndApplySelection();

  // 0x5dea60 — allocates a TModalMessageCommand carrying `message`/`payload`, seeds
  // it with dispatch code 'Hey!' targeting the global UI root controller, and posts
  // it there. `this` is unused by the original body.
  void CreateModalMessageCommandAndQueue(CString* message, int payload);
  // Mac oracle: TViewMgr::ModalMessage(CStr255, const VPoint&) and the four-argument
  // overload. Windows substitutes CString/POINT but preserves the value/reference shape.
  void ModalMessage(CString message, const POINT& messagePosition);
  char ModalMessage(CString message, const POINT& messagePosition, short overlayMode,
                    unsigned char showCancel);
  // 0x5de990 — load string (group, index) and pose it through the localized-message
  // dispatch; returns the prompt result byte.
  char ShowLocalizedUiPromptByGroupAndIndex(int uiStringGroup, int uiStringIndex, int overlayMode,
                                            int arg4);
  // 0x5de8f0 — resolve the turn-event dialog node for message context 0x101a, place it,
  // capture its layout, refresh it, then run its void tail hook and free it.
  void DispatchUiRuntimeMessage101AAndRefreshActiveView();
  // 0x5deb40 — pose the confirm prompt matching `actionTag` ('magc'/'gwen'/'quit'/
  // 'load'; group 0x2737 index by game-flow mode) and, when accepted during session
  // teardown, dispatch the 'abdi' game-state event. Returns the accepted byte.
  char DispatchGameStateEventIfLocalizedPromptAccepted(int actionTag);
  // Mac oracle: TViewMgr::ModalMessage(long, CStr255, CStr255, const VPoint&, short,
  // unsigned char). This overload formats and presents the actual modal message window.
  char ModalMessage(long templateKind, CString formatText, CString message,
                    const POINT& messagePosition, short overlayMode, unsigned char showCancel);

  // 0x5de4f0. Shows the Civilian Report confirmation dialog (resource 0xbc4) for
  // pCivilianOrderEntry, fills its 'DLOG' civilian-report control, runs the modal dialog,
  // and returns true iff the player picked "confirm" ('okay').
  bool ShowCivilianReportDialogAndReturnConfirm(class TCivUnit* pCivilianOrderEntry);

  // 0x5d5d30 (ret 0x1c). The shared nation-info/modal-message implementation driven by
  // BuildAndShowTurnOverlayByMode: resolves the turn-event dialog (message context
  // 0x7e4, or 0x2508 after the TAssetMgr slot-0xc notify when eventPayload carries a
  // resource word after a -1000 sentinel), fills the 'GOLD'/'coat'/'awer'/'titl'/'info'
  // children, wraps the info text in a fresh TScrollView when it overflows, plays the
  // per-mode sfx, runs the modal loop, and returns false only for a 'cncl' close.
  // (Ghidra's TCivToolbar attribution was wrong: the placement dispatch is this class's
  // own virtual slot 0x11 and the only caller passes TViewMgr's `this`.)
  bool RunNationInfoModalAndReturnNonCancel(int messageKind, CString titleSuffix,
                                            const char* messageChars, int messageLength,
                                            const POINT& messagePosition, int contextTag,
                                            char showCancel);

  // 0x5de5d0 (ret 0x8). Resolves the turn-event dialog node for message context 0xc1c,
  // marks it via TWindow::SetField84(1) (same idiom as MakePlanetSeedDialog),
  // resolves its 'DLOG'-tagged child control, and forwards cityRecordIndex/
  // categoryCounts into TArmyInfoView's slot-0x1cc dispatch, finally comparing the
  // dialog's result tag to 'okay'.
  bool DispatchProvinceOrderOverlayConfirmDialog(short cityRecordIndex, int* categoryCounts);

  // Mac oracle: TViewMgr::MakePlanetSeedDialog(const char*, CStr32&, const char*,
  // const char*, int, unsigned char) const. Windows uses CString for the CStr32 value
  // and returns the selected four-character control tag. 0x5de010.
  int MakePlanetSeedDialog(const char* instruction, CString& planetSeed, const char* firstChoice,
                           const char* secondChoice, int initialChoice,
                           unsigned char showCancel) const;

  // Object layout recovered from ctor 0x5d5060 / ReadFrom 0x5d5200 /
  // LoadTurnEventCursorTable 0x5d5100. Field names past the event code are
  // provisional. Total size 0xfc, base TObject = 0x4.
  void RefreshTechnologyStorePageAndHudText(int nationSlot); // 0x005d8750

  TurnEventCodeStorage currentTurnEventCode; // +0x04 (turn-event dispatch code)
  short currentTurnEventNationSlot06;        // +0x06
  POINT dialogPlacement08; // +0x08 (seeded from g_ptCitySiteSelectionDialogPlacement)
  unsigned char field10;   // +0x10
  unsigned char pad11[3];  // +0x11
  // +0x14 .. 0xeb (54 turn-event cursor handles). Indexed as
  // turnEventCursors[resourceCursorId - kCursorResourceIdBase] -- confirmed against
  // TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback's ground-truth
  // `[EAX + EDX*4 + 0xfffff074]` (0xfffff074 == -0xf8c == 0x14 - kCursorResourceIdBase*4).
  HCURSOR turnEventCursors[0x36];
  short fieldEc;                           // +0xec
  short padEe;                             // +0xee
  class TMapUberPicture* mapUberPictureF0; // +0xf0
  TMovieView* activeMovieViewF4;           // +0xf4
  short fieldF8;                           // +0xf8
  short padFa;                             // +0xfa

  TViewMgr();

  // Screen-exit backbone: stash the followup turn state in fieldF8; on state 0,
  // re-apply volume preferences and post the followup turn-event code (0x5dc menu /
  // 0x7e0 / 0x5eb) via g_pGlobalUiRootController->PostTurnEventCodeMessage2420.
  void HandleTurnStateExitAndPostFollowupEventCode(short followupState); // 0x5db620
};

ASSERT_SIZE(TViewMgr, 0xfc);
