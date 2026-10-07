#pragma once

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/mfc.h"
#include "game/quickdraw_types.h"
#include "game/turn_event_codes.h"

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

  void MakeCheaterDialog(int which);
  virtual void MakeGameSetupDialog();                                          // slot 0x0b 0x5dcaa0
  virtual void SetBackColor(short colorCode);                                  // slot 0x0c 0x5d5780
  virtual void SetForeColor(short colorCode);                                  // slot 0x0d 0x5d5750
  virtual int ClassifyTurnStateForOverlayMode();                               // slot 0x0e 0x5d5960
  virtual void BuildAndShowTurnOverlayByMode(int overlayMode, int contextArg); // slot 0x0f 0x5d6480
  virtual void VerifyEndTurn();                                                // slot 0x10 0x5d57b0
  virtual void GetTopLeftFor(TView* dialogView,
                             POINT* outPlacement);                  // slot 0x11 0x5d69b0
  virtual void RefreshMainViewNationIndicatorForCurrentTurnEvent(); // slot 0x12 0x5d6b70

  // Extended UI-runtime virtuals (same object as g_pViewMgr @ 0x006A21BC).
  virtual void DispatchTurnEvent(TurnEventCodeStorage eventCode, int payload); // 0x4c
  virtual void SetCursorRangeAndRefreshMainPanel(int payload);                 // 0x50
  virtual short GetPendingTurnOverlayCode();                                   // 0x54
  virtual void RefreshStrategicMapStatusIconsForActiveNation();                // 0x58
  virtual void RefreshTradeAndIndustryOverviewScreen(int nationIndex);         // 0x5c
  virtual void RefreshMainDialogAndCursorHelp(int eventCode);                  // 0x60
  virtual void ShowDealBookScreen(short nationSlot);                           // 0x64; Mac oracle

  // UI runtime helper functions
  virtual void AddPendingTurnOverlayCode(int modeValue);       // 0x68
  virtual void ShowDiplomacyScreen(short nationSlot);          // 0x6c; Mac oracle
  virtual void MakeRelationshipDialog(int dialogContext);      // 0x70 0x5d6cd0
  virtual void MakeMinorsTradeBidsDialog(int dialogContext);   // 0x74 0x5d6d70
  virtual void MakeMinorRelationshipDialog(int dialogContext); // 0x78 0x5d6e50
  virtual void MakeGPTreatyDialog(int dialogContext);          // 0x7c 0x5d6f10
  virtual void MakeMinorTreatyDialog(int dialogContext);       // 0x80 0x5d6fd0
  virtual void ShowTransportScreen(short nationSlot);          // 0x84; Mac oracle
  virtual void ShowAbilityStatusReport(short abilityIndex);    // 0x88 0x5d8980 (ret 4)
  virtual void NoOpTurnEventStateVtableSlot8C(int arg);        // 0x8c
  virtual bool MakeDiplomacyOfferDialog(short sourceNation, short targetNation,
                                        short proposalCode); // 0x90
  virtual char MakeWarOfferDialog(int sourceNation, int minorNationSlot, int enemyNationSlot,
                                  int promptCode); // 0x94
  virtual void ShowOfferSheet(short respondingNation, short offeringNation, short proposedAmount,
                              short maxAmount, short commodityType); // 0x98; Mac oracle
  virtual void ShowNewspaper(int pageIndex = 0);                     // 0x9c; Mac oracle uses long
  virtual void SyncTacticalStatusPanelRegion();                      // 0xa0
  virtual void ShowCitySiteSelectorAndWait(int payload,
                                           TEventHandler* waitTarget); // 0xa4
  virtual void ShowCityProductionView(short nationSlot);               // 0xa8; Mac oracle
  virtual void UpdateCityScreen();                                     // 0xac 0x5d7f70
  virtual void CloseBuilding(short buildingSlot);                      // 0xb0 0x5d7f90
  virtual bool MakeNewTownDialog(TTown* town);                         // 0xb4 0x5dcdf0
  virtual void ShowBuildingExpansionDialog(short buildingSlotId, class TCity* city,
                                           class TCityProductionView* productionView); // 0xb8
  virtual void ShowTerrainMap(short nationSlot);                           // 0xbc; Mac oracle
  virtual void CreateMapArtStorage();                                      // 0xc0 0x5dc180
  virtual void GenerateMiniMap();                                          // 0xc4 0x5dc1c0
  virtual void GenerateRegions();                                          // 0xc8 0x5dc1a0
  virtual void RefreshActiveGoldControlAndUiRuntimeState();                // 0xcc 0x5dc160
  virtual void InitializeCitySiteSelectionScreenForNation(int nationSlot); // 0xd0
  virtual void NoOpTurnEventStateVtableSlotD4(int arg);                    // 0xd4
  virtual void MakeCombatReport(TCombatReportContext* reportContext);      // 0xd8 0x5dcf20
  virtual int MakeEngineeringDialog(int dialogValue = 0);                  // 0xdc
  virtual void HandleGlobalMapNationContextSelection(int nationSlot, int unused = 0); // 0xe0
  // Modal town-name notice; stringCode indexes the town-names string list.
  virtual void ShowTownNameDialog(int stringCode);                            // 0xe4
  virtual void ShowUnreachableCityDialog(void* selection);                    // 0xe8
  virtual void MakeGarrisonWindow(int tileIndex);                             // 0xec; Mac oracle
  virtual TNavyRoster* MakeNavyRosterDialog(TTaskForce* activeMapOrderEntry); // 0xf0
  virtual void StartPhaseMovie();                                             // 0xf4
  virtual void SetUpMainMenuScreen();                                         // 0xf8
  virtual void NoOpTurnEventStateVtableSlotFC();  // 0xfc 0x5dbd10 -- real body is a bare `ret`
  virtual void ShowLoadSaveScreen();              // 0x100 0x5dbd30; Mac oracle
  virtual void ShowScenarioScreen();              // 0x104; Mac oracle
  virtual void ShowHighScoreScreen();             // 0x108; Mac oracle
  virtual void ConfigureMapEditorGoldValueGrid(); // 0x10c 0x5dc3f0
  virtual void ShowUnitHistory(short nationSlot); // 0x110 0x5dc690

  QuickDrawPaletteIndex GetColor(short colorCode);
  void SetColor(short colorCode, bool foreground);

  void ShowCivilianLedgerDialogAndSelectUnit();
  void ShowArmyRosterDialogAndActivateProvinceSelection();
  void ShowNavyRosterDialogAndApplySelection();

  void PostModalMessage(CString* message, int payload);
  void ModalMessage(CString message, const POINT& messagePosition);
  bool ModalMessage(CString message, const POINT& messagePosition, short overlayMode,
                    unsigned char showCancel);
  bool ModalMessageGateAssertStub(CString message, int arg2, int arg3, int arg4, int arg5,
                                  int arg6);
  bool ShowLocalizedUiPromptByGroupAndIndex(int uiStringGroup, int uiStringIndex, int overlayMode,
                                            int arg4);
  void DispatchUiRuntimeMessage101AAndRefreshActiveView();
  char DispatchGameStateEventIfLocalizedPromptAccepted(int actionTag);
  bool ModalMessage(long templateKind, CString titleSuffix, CString message,
                    const POINT& messagePosition, short overlayMode, unsigned char showCancel);

  bool MakeCivInfoWindow(class TCivUnit* pCivilianOrderEntry);

  bool RunNationInfoModalAndReturnNonCancel(int messageKind, CString titleSuffix,
                                            const char* messageChars, int messageLength,
                                            const POINT& messagePosition, short contextTag,
                                            char showCancel);

  bool MakeArmyInfoWindow(short cityRecordIndex, int* categoryCounts);

  int MakePlanetSeedDialog(const char* instruction, CString& planetSeed, const char* firstChoice,
                           const char* secondChoice, int initialChoice, bool showCancel) const;

  void RefreshTechnologyStorePageAndHudText(int nationSlot); // 0x005d8750

  TurnEventCodeStorage currentTurnEventCode; // +0x04 (turn-event dispatch code)
  short currentTurnEventNationSlot;          // +0x06
  POINT dialogPlacement;   // +0x08 (seeded from g_ptCitySiteSelectionDialogPlacement)
  bool waitOverlayPending; // +0x10
  unsigned char pad11[3];  // +0x11
  HCURSOR turnEventCursors[0x36];
  short pendingTurnOverlayCode;          // +0xec
  short padEe;                           // +0xee
  class TMapUberPicture* mapUberPicture; // +0xf0
  TMovieView* activeMovieView;           // +0xf4
  short pendingFollowupState;            // +0xf8
  short padFa;                           // +0xfa

  TViewMgr();

  void HandleTurnStateExitAndPostFollowupEventCode(short followupState); // 0x5db620
};

ASSERT_SIZE(TViewMgr, 0xfc);
