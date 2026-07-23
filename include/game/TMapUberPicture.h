#pragma once

#include "game/TMapUberUberPicture.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TTaskForce;
class TZone;
class TNavyRoster;
class TWorldView;
class TMiniMapView;
class TMapDialog;
class TOceanDialog;

// VTABLE: IMPERIALISM 0x00668f08
class TMapUberPicture : public TMapUberUberPicture {
public:
  DECLARE_DYNCREATE(TMapUberPicture)
  virtual ~TMapUberPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;        // slot 0x07 0x596c60
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override;                    // slot 0x0f 0x00597340
  virtual void DoMenuCommand(int param) override;                  // slot 0x11 0x597600
  virtual void DoKeyEvent(TToolboxEvent* event) override;          // slot 0x12 0x597770
  virtual void DoPostCreate(int arg) override;                     // slot 0x37 0x596a80
  virtual void Scroll(MapScrollEdgeMaskStorage edgeMask) override; // slot 0x74 0x5977a0
  // Mac CodeWarrior identity: TMapUberPicture::InvalidateMap(). Refreshes whichever
  // concrete map dialog is active.
  virtual void InvalidateMap(); // slot 0x75 0x598950
  // Mac CodeWarrior identity: TMapUberPicture::InvalidateTile(short). Dispatches to the
  // active land or ocean map dialog.
  virtual void InvalidateTile(short tileIndex); // slot 0x76 0x598870
  // Mac CodeWarrior identities for the navigation/redraw virtuals. Each forwards to the
  // active land/ocean map view and keeps the land cache or mini-map in sync.
  virtual void RedrawTile(short tileIndex); // slot 0x77 0x5988c0
  // CenterOn/SetUpperLeft consume promoted stack dwords at these virtual boundaries.
  virtual void CenterOn(int tileIndex);                                   // slot 0x78 0x598990
  virtual void SetUpperLeft(int tileX, int tileY);                        // slot 0x79 0x5989d0
  virtual void NoticeTile(int tileIndex);                                 // slot 0x7a 0x598a20
  virtual bool HasActiveMapInteractionSelection();                        // slot 0x7b 0x597a10
  virtual void PrepareAndRenderMapOverlayMode(unsigned char overlayMode); // slot 0x7c 0x598910
  // Ground truth (final RET has no operand) proves the previous 1-arg
  // __fastcall(astruct_20*)/void-return declaration was a poison-pill: real signature is
  // thiscall, 0 explicit args; the caller-visible "return value" is just SetTrade-
  // ToolSubcontrolEnabledStateByFlag's incidental EAX forwarded through, not a distinct
  // result of this function's own.
  virtual void DisplayMiniMap(); // slot 0x7d 0x599cf0
  virtual void RemoveMiniMap();  // slot 0x7e 0x599fd0
  // Ground truth (RET 0x4) proves the previous 0-arg declaration was a poison-pill: real
  // signature takes the enabled-state flag applied to the 'seas'/'year'/'trea'/'tree'
  // trade-tool subcontrols.
  virtual void SetTradeToolSubcontrolEnabledStateByFlag(bool enabledState); // slot 0x7f 0x59a180

  // Own slice (TMapUberUberPicture ends at 0x94; this object is 0xc4). Layout/roles from
  // ConstructTMapUberPictureBaseState (0x5969e0) and DoPostCreate (0x596a80).
  // Set to 1 by the ctor; read by SetActiveMapOrderEntry to gate
  // InvalidateMapRegionForOrderEntry calls around orderEntryContext98 updates (matches
  // TWorldView.cpp's independently-derived TMapOrderToolbarPendingState::invalidationFlag).
  unsigned char invalidationFlag94;
  // 0=civilian, 1=army, 2=navy, 3=none (default) -- selects categoryPages[] below.
  short activeUnitCategoryIndex96;
  // The currently-selected map-order context node -- a TZone (map-action context), not a
  // TTaskForce: its CreateTaskForceFromNavyOrders... factory produces the task force
  // panel shown for it (SetActiveMapOrderEntry/RefreshMapOrderEntryPanel).
  TZone* orderEntryContext98;
  // Windows field-xrefs find only the constructor's zero write at +0x9c.
  int unresolvedZero9C;
  // Mac TMapUberPicture::UpdateRoster (Windows 0x599a20) refreshes this page at its
  // currentPage. The Combined Map resource identifies the enclosing 'main' receiver as
  // TMapUberPicture; the pointed-to page is optional.
  TNavyRoster* navyRosterA0;
  // Optional 'DOOG' child used by the 0x7dd dual-map factory. Its factory constructs a
  // TOceanDialog, and Scroll calls ApplyDirectionalNudgeAndRefreshDisplay
  // directly when that child is active.
  TOceanDialog* goodGoldTagControlA4;
  // The 'DLOG' child. Event 0x3b8 constructs a TCitySiteView (a TMapDialog subclass),
  // while event 0x7dd constructs TMapDialog directly. The slot-0xa4 dispatch in
  // Scroll resolves to
  // TMapDialog::UpdateMapInteractionPreviewParityAndRenderTransientSprites.
  TMapDialog* subview2A8;
  // Active strategic-map dialog. Both TMapDialog and TOceanDialog derive from TWorldView;
  // this common-base type allows the original land/ocean switch without a cast.
  TWorldView* subviewAc;
  // 0xb0..0xbf: per-category ('uciv'/'uarm'/'unav'/unused) sub-controls resolved by
  // DoPostCreate via ResolveControlByTag. NOT a homogeneous TMapUberPicture array
  // (that was the old theory): bd 4yz's evidence disproves it two ways. (a) TCivMgr's
  // SetActiveCivilianSelection (0x4d2c60) makes a direct non-virtual call from
  // categoryPages[0] to TCivToolbar::RefreshCivilianCommandPanelForSelection (0x58eb20,
  // ground-truth-confirmed, not a vtable dispatch), which only produces correct behavior
  // if categoryPages[0] really is a TCivToolbar object. (b) TArmyMgr's
  // SetActiveProvinceSelection (0x4a45e0) dispatches categoryPages[1]'s own vtable slot at
  // byte offset 0x1d0 -- but TArmyToolbar's real vtable (dumped at 0x667ad0) is far larger
  // than TMapUberPicture's (entries confirmed past index 0xb7), and slot 0x1d0 there
  // resolves to TArmyToolbar's own 0x58df60, not TMapUberPicture::Scroll.
  // So categoryPages[] is genuinely heterogeneous per index (civ=TCivToolbar,
  // army=TArmyToolbar, navy presumably TNavyToolbarCluster) -- distinct TView-derived
  // hierarchies, not further TMapUberPicture instances. TView is their true common
  // ancestor (TCivToolbar/TArmyToolbar: TView<-...<-TCluster<-TControl chain;
  // TMapUberPicture: TView<-TEventHandler<-TPicture<-... chain), which is why
  // SetMapInteractionMode's own categoryPages[]->CaptureLayoutF0 calls (a slot inherited
  // unchanged at the same byte offset in every one of these subclasses) work regardless of
  // the concrete type. Callers that need a concrete page (TCivMgr.cpp) downcast with
  // static_cast<TCivToolbar*> at the specific call site instead of typing the whole array
  // to one caller's concrete class.
  TView* categoryPages[4];
  // The mini-map tool-window created by DisplayMiniMap (0x599cf0), which
  // allocates a TMiniMapView (vtable 0x669170, size 0xa0), sets its owner backref, and
  // stores the result here.
  TMiniMapView* miniMapViewC0;

  TMapUberPicture();

  // Sets the active map-interaction mode (0=civilian, 1=army, 2=navy, 3=none), clearing
  // the previous mode's selection state (TCivMgr/TArmyMgr singleton), refreshing the
  // mode-caption text, and dispatching CaptureLayoutF0 on the old/new categoryPages[]
  // entries. 0x00596cb0, __thiscall, 1 arg. Curated in symbols.csv as
  // `TToolBarCluster::SetMapInteractionMode`, but this callsite's own disassembly reads
  // activeUnitCategoryIndex96/categoryPages[] at their real TMapUberPicture offsets --
  // moved here rather than left mis-attributed (see also TWorldView.cpp's own
  // independent caveat about the same object).
  void SetMapInteractionMode(short nMode);
  // Refreshes the mini-map tool window if it exists. Null-receiver-safe:
  // call sites invoke this on a possibly-null ownerContext. 0x00599fa0, __thiscall,
  // 0 args.
  void InvalidateMiniMap();
  // Refreshes the 4 order-quota slider controls ("0slc".."3slc") from
  // orderEntryContext98, or clears them if it's null. 0x00597810, __thiscall, 1 arg.
  void RefreshMapOrderEntryPanel(TTaskForce* pMapOrderEntry);
  // Leaves the alternate zoomed-out ("ZmOt") map mode: asserts/retags the zoom-out control
  // ('controlOverride' when non-null, else resolved by tag 'ZmOt') back to 'ZmIn', clears
  // invalidationFlag94, and restores subviewAc to goodGoldTagControlA4. 0x00599b90,
  // __thiscall, 1 arg (a TView* override for the zoom control, or null to resolve it).
  void CommitPendingUiModeChangeAndRefreshViews(TView* controlOverride);
  // Sets orderEntryContext98 (invalidating the old/new map regions around the write),
  // then calls RefreshMapOrderEntryPanel. 0x00597950, __thiscall, 1 arg.
  void SetActiveMapOrderEntry(TZone* pMapOrderContextZone);
  // Invalidate one navy-order zone only while the alternate ocean view is active.
  // 0x00598840, __thiscall; previously mis-attributed to TToolBarCluster.
  void InvalidateMapRegionForEntryIfUiPassive(TZone* zone);
  // Scan the navy-order context chain from either the current entry or its successor,
  // select the first displayable entry, and refresh the navy panel. 0x005998a0.
  bool TrySelectNextValidMapOrderEntry(char includeCurrent);
  // Mode-guarded void sibling used by click/navigation paths. 0x00599770.
  void SelectNextValidMapOrderEntryFromCursor(char includeCurrent);
  // Enters/exits the mode-specific overlay UI state (called from SetMapInteractionMode
  // when switching to civilian mode). 0x00599a50, 252 bytes.
  void EnterMapInteractionOverlayMode(TView* controlOverride);
  // Resets map interaction back to civilian-selection mode: enters the overlay mode with
  // no explicit control, then sets interaction mode 0. 0x005999f0, __thiscall, 0 args.
  void ResetMapInteractionToCivilianMode();
  // Mac oracle: UpdateRoster(). Refresh the optional roster page without changing its
  // current page. 0x00599a20.
  void UpdateRoster();
  // Cycles map interaction selection to the next civilian/province/map-order candidate
  // after a handled click (priority: civilian, then province, then map-order entry;
  // clears the active pointer if none remain). 0x00597a80, __thiscall, 0 args, 996 bytes.
  // Re-attributed from a `TCivToolbar::` mis-label (symbols.csv/bd 4yz): its body reads
  // this+0x96 (activeUnitCategoryIndex96, MOV BL,byte[ESI+0x96]) and both real call sites
  // (TCivMgr::OrderAndCycle's thunk 0x408b93, and
  // TArmyToolbar.cpp's own call) load ECX from g_pUiRuntimeContext->mapUberPictureF0
  // directly -- ground-truth-confirmed via `just ghidra listing`, not a categoryPages[]
  // dispatch.
  void CycleMapInteractionSelectionAfterHandledClick();
  // Mac oracle: NavalIntelligenceDialog(TZone*, short, TTaskForce*). Opens the
  // MapView.rsrc:9475 "Enemy Fleet Report" tree (event 0x2503); nation selects the
  // foreign power and cachedTaskForce switches between direct and estimated reports.
  void NavalIntelligenceDialog(TZone* zone, short nation, TTaskForce* cachedTaskForce);
  // Mac oracle: InspectTaskForceDialog(TTaskForce*). Opens MapView.rsrc:9474,
  // event 0x2502 ("Friendly Fleet Report"), and cancels the order when requested.
  void InspectTaskForceDialog(TTaskForce* taskForce);
  // Windows navy-order creation dialog backed by Mac MapView.rsrc:9462 (event 0x24f6,
  // "Navy Maker II"). Applies the fourteen per-ship counts to the selected port zone.
  void RunNavyPrimaryOrderCreationDialogAndApplyResults(TZone* portZone);
};
