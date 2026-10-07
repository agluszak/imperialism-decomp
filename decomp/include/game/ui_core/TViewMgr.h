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
  virtual ~TViewMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  virtual void LoadTurnEventCursorTable();

  void MakeCheaterDialog(int which);
  virtual void MakeGameSetupDialog();
  virtual void SetBackColor(short colorCode);
  virtual void SetForeColor(short colorCode);
  virtual int ClassifyTurnStateForOverlayMode();
  virtual void BuildAndShowTurnOverlayByMode(int overlayMode, int contextArg);
  virtual void VerifyEndTurn();
  virtual void GetTopLeftFor(TView* dialogView, POINT* outPlacement);
  virtual void RefreshNationIndicator();

  // Extended UI-runtime virtuals (same object as g_pViewMgr @ 0x006A21BC).
  virtual void DispatchTurnEvent(TurnEventCodeStorage eventCode, int payload);
  virtual void SetCursorRangeAndRefreshMainPanel(int payload);
  virtual short GetPendingTurnOverlayCode();
  virtual void RefreshStatusIcons();
  virtual void RefreshTradeAndIndustryOverviewScreen(int nationIndex);
  virtual void RefreshMainDialogAndCursorHelp(int eventCode);
  virtual void ShowDealBookScreen(short nationSlot);

  // UI runtime helper functions
  virtual void AddPendingTurnOverlayCode(short modeValue);
  virtual void ShowDiplomacyScreen(short nationSlot);
  virtual void MakeRelationshipDialog(int dialogContext);
  virtual void MakeMinorsTradeBidsDialog(int dialogContext);
  virtual void MakeMinorRelationshipDialog(int dialogContext);
  virtual void MakeGPTreatyDialog(int dialogContext);
  virtual void MakeMinorTreatyDialog(int dialogContext);
  virtual void ShowTransportScreen(short nationSlot);
  virtual void ShowAbilityStatusReport(short abilityIndex);
  virtual void NoOpTurnEventStateVtableSlot8C(int arg);
  virtual bool MakeDiplomacyOfferDialog(short sourceNation, short targetNation, short proposalCode);
  virtual char MakeWarOfferDialog(int sourceNation, int minorNationSlot, int enemyNationSlot,
                                  int promptCode);
  virtual void ShowOfferSheet(short respondingNation, short offeringNation, short proposedAmount,
                              short maxAmount, short commodityType);
  virtual void ShowNewspaper(int pageIndex = 0); // Mac oracle uses long
  virtual void SyncTacticalStatusPanelRegion();
  virtual void ShowCitySiteSelectorAndWait(int payload, TEventHandler* waitTarget);
  virtual void ShowCityProductionView(short nationSlot);
  virtual void UpdateCityScreen();
  virtual void CloseBuilding(short buildingSlot);
  virtual bool MakeNewTownDialog(TTown* town);
  virtual void ShowBuildingExpansionDialog(short buildingSlotId, class TCity* city,
                                           class TCityProductionView* productionView);
  virtual void ShowTerrainMap(short nationSlot);
  virtual void CreateMapArtStorage();
  virtual void GenerateMiniMap();
  virtual void GenerateRegions();
  virtual void RefreshGoldControl();
  virtual void ShowCitySiteMap(int nationSlot);
  virtual void NoOpTurnEventStateVtableSlotD4(int arg);
  virtual void MakeCombatReport(TCombatReportContext* reportContext);
  virtual int MakeEngineeringDialog(short dialogValue = 0);
  virtual void HandleGlobalMapNationContextSelection(int nationSlot, int unused = 0);
  // Modal town-name notice; stringCode indexes the town-names string list.
  virtual void ShowTownNameDialog(short stringCode);
  virtual void ShowUnreachableCityDialog(void* selection);
  virtual void MakeGarrisonWindow(short tileIndex);
  virtual TNavyRoster* MakeNavyRosterDialog(TTaskForce* activeMapOrderEntry);
  virtual void StartPhaseMovie();
  virtual void SetUpMainMenuScreen();
  virtual void NoOpTurnEventStateVtableSlotFC(); // real body is a bare `ret`
  virtual void ShowLoadSaveScreen();
  virtual void ShowScenarioScreen();
  virtual void ShowHighScoreScreen();
  virtual void ConfigureMapEditorGoldValueGrid();
  virtual void ShowUnitHistory(short nationSlot);

  QuickDrawPaletteIndex GetColor(short eventCode);
  void SetColor(short colorCode, bool foreground);

  void ShowCivilianLedgerDialogAndSelectUnit();
  void ShowArmyRoster();
  void ShowNavyRosterDialogAndApplySelection();

  void PostModalMessage(CString* message, int payload);
  void ModalMessage(CString message, const POINT& messagePosition);
  bool ModalMessage(CString message, const POINT& messagePosition, short overlayMode,
                    unsigned char showCancel);
  bool ModalMessageGateAssertStub(CString message, int arg2, int arg3, int arg4, int arg5,
                                  int arg6);
  bool ShowLocalizedUiPromptByGroupAndIndex(int uiStringGroup, int uiStringIndex, int overlayMode,
                                            int arg4);
  void ShowQueryWindow();
  char ConfirmGameControl(int actionTag);
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

  void RefreshTechnologyStorePageAndHudText(int nationSlot);

  TurnEventCodeStorage currentTurnEventCode; // (turn-event dispatch code)
  short currentTurnEventNationSlot;
  POINT dialogPlacement; // (seeded from g_ptCitySiteSelectionDialogPlacement)
  bool waitOverlayPending;
  unsigned char pad11[3];
  HCURSOR turnEventCursors[54];
  short pendingTurnOverlayCode;
  class TMapUberPicture* mapUberPicture;
  TMovieView* activeMovieView;
  short pendingFollowupState;

  TViewMgr();

  void ExitTurnState(short followupState);
};

ASSERT_SIZE(TViewMgr, 0xfc);
