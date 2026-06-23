#include "game/TViewMgr.h"
#include "game/TAssetMgr.h"
#include "game/TToolBarCluster.h" // pulls TView/TControl/TCluster chain for main-view dispatch
#include "game/UiRuntimeContext.h"
#include "game/diplomacy_globals.h"  // g_pGameFlowState
#include "game/turn_flow_cooldown.h" // IsTurnCooldownCounterActiveOrResetFlag

// TSimMgr global instance @ 0x6a20f8 (a.k.a. g_pLocalizationTable / turn-state
// manager). Forward-declared here to avoid pulling the full TSimMgr header.
class TSimMgr;
extern "C" TSimMgr* g_pLocalizationTable;

// Application/document root pointer @ 0x6a2158; its +0x04 field holds the active main
// TView used as the dispatch root for turn-event UI refreshes.
namespace {
struct MainViewHostContext {
  void* field0;    // +0x00
  TView* mainView; // +0x04
};
const unsigned int kAddrMainViewHostPtr = 0x006a2158;
} // namespace

// Free-function thunks reached through the ILT jump table; declared in the generic
// repo form and invoked through typed __cdecl casts at the callsites.
undefined4 LoadTurnEventCursorByResourceIdOffset1000(void);
undefined4 MapTurnEventCodeToPaletteIndex(void);
undefined4 SetQuickDrawFillColorFromPaletteIndex(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
// Returns the active AFX thread's main window object (its +0x1c field is the host HWND).
undefined4 InvokeAfxThreadVslot7CAndGetValueAtOffset98(void);
// ILT thunk (generic form per repo policy; typed cast applied at the callsite).
undefined4 thunk_TemporarilyClearAndRestoreUiInvalidationFlag(void);

// Provisional dispatch interfaces for the runtime-resolved turn-event dialog node (a
// TView-family panel; the concrete class is registry-driven) and its 'GOLD' child
// control. Only the subclass-introduced slots are declared; the lower slots
// (ResolveControlByTag, CaptureLayoutF0, CallVoidSlotA0, Free, AssertValid) are
// inherited and dispatched as real virtuals. No VTABLE/ctor — these are never
// constructed here, only used to dispatch through the runtime object's vtable.
namespace {
struct TurnEventDialogNode : public TView {
  virtual void ShowTurnEventDialog(int flag);  // slot 0x68 byte 0x1a0
  virtual void node_vmethod_0069();            // slot 0x69
  virtual void node_vmethod_006a();            // slot 0x6a
  virtual void RefreshTurnEventDialog();       // slot 0x6b byte 0x1ac
  virtual void node_vmethod_006c();            // slot 0x6c
  virtual void node_vmethod_006d();            // slot 0x6d
  virtual void* QueryTurnEventContentObject(); // slot 0x6e byte 0x1b8
};
struct GoldDialogControl : public TControl {
  virtual void gold_vmethod_0071();                         // slot 0x71 byte 0x1c4
  virtual void SetGoldControlStateByResource(int a, int b); // slot 0x72 byte 0x1c8
};
// g_pUiViewManager (TAssetMgr) @ 0x6a2148 — the UI/view asset registry that resolves
// turn-event dialog nodes by message context.
const unsigned int kAddrUiViewManagerPtr = 0x006a2148;
const unsigned int kAddrStrNilPointer = 0x00694fc8;
const unsigned int kAddrStrFailure = 0x00694fd8;
const unsigned int kAddrStrSourceFile = 0x0069b6bc;
} // namespace

namespace {
const unsigned int kAddrClassDescTViewMgr = 0x0066f0b8;
const unsigned int kAddrTurnStateSeedLo = 0x006a5b58;
const unsigned int kAddrTurnStateSeedHi = 0x006a5b5c;
} // namespace

// FUNCTION: IMPERIALISM 0x005d5040
CRuntimeClass* TViewMgr::GetRuntimeClass() const {
  return reinterpret_cast<CRuntimeClass*>(kAddrClassDescTViewMgr);
}

// FUNCTION: IMPERIALISM 0x005d5060
TViewMgr::TViewMgr() : TObject() {
  this->fieldEc = 0;
  this->currentTurnEventCode = 0;
  this->turnStateSeedLo = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedLo);
  this->turnStateSeedHi = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedHi);
  this->field10 = 0;
  this->fieldF0 = 0;
  this->fieldF4 = 0;
  this->fieldF8 = 0;
}

// SYNTHETIC: IMPERIALISM 0x005d50b0
// TViewMgr::`scalar deleting destructor'
TViewMgr::~TViewMgr() {}

// FUNCTION: IMPERIALISM 0x005d5100
void TViewMgr::LoadTurnEventCursorTable() {
  for (int i = 0; i < 0x36; i++) {
    this->cursorTable[i] =
        reinterpret_cast<void*(__cdecl*)(int)>(LoadTurnEventCursorByResourceIdOffset1000)(i + 1000);
  }
}

// FUNCTION: IMPERIALISM 0x005d51e0
void TViewMgr::Free() {
  delete this;
}

// FUNCTION: IMPERIALISM 0x005d5200
void TViewMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  this->fieldEc = 0;
  this->currentTurnEventCode = 0;
  this->turnStateSeedLo = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedLo);
  this->turnStateSeedHi = *reinterpret_cast<unsigned int*>(kAddrTurnStateSeedHi);
  this->field10 = 0;
  this->fieldF0 = 0;
}

// FUNCTION: IMPERIALISM 0x005d5250
void TViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x005d5750
void TViewMgr::ApplyTurnEventPaletteColorByEventCode(int eventCode) {
  int paletteIndex =
      reinterpret_cast<int(__cdecl*)(int)>(MapTurnEventCodeToPaletteIndex)(eventCode);
  reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColorFromPaletteIndex)(paletteIndex);
}

// FUNCTION: IMPERIALISM 0x005d5780
void TViewMgr::UpdatePaletteIndexFromTurnEventCode(int eventCode) {
  int paletteIndex =
      reinterpret_cast<int(__cdecl*)(int)>(MapTurnEventCodeToPaletteIndex)(eventCode);
  reinterpret_cast<void(__cdecl*)(int)>(UpdatePaletteIndexWithDefaultFallback)(paletteIndex);
}

// FUNCTION: IMPERIALISM 0x005d57b0
void TViewMgr::HandleTurnEventVtableSlot40RefreshGoldDialog() {
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  TAssetMgr* uiViewManager = *reinterpret_cast<TAssetMgr**>(kAddrUiViewManagerPtr);
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      uiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x7e5));
  if (node == nullptr) {
    MessageBoxA(nullptr, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    reinterpret_cast<void(__cdecl*)(const char*, int)>(
        thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(
        reinterpret_cast<const char*>(kAddrStrSourceFile), 0x223);
  }
  node->ShowTurnEventDialog(1);
  if (node->ResolveControlByTag(0x444c4f47) == nullptr) { // 'GOLD'
    MessageBoxA(nullptr, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    reinterpret_cast<void(__cdecl*)(const char*, int)>(
        thunk_TemporarilyClearAndRestoreUiInvalidationFlag)(
        reinterpret_cast<const char*>(kAddrStrSourceFile), 0x227);
  }
  void* content = node->QueryTurnEventContentObject();
  if (content != nullptr) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(content) + 0x14) = 0x70696335; // 'cip5'
  }

  POINT placement;
  this->ComputeTurnEventDialogPlacementByCode(node, &placement);
  node->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);

  GoldDialogControl* gold = static_cast<GoldDialogControl*>(node->ResolveControlByTag(0x444c4f47));
  gold->AssertValid();
  gold->SetGoldControlStateByResource(0x24cd, 0);

  // Mask the game-flow flag while committing the refresh when localization mode is active.
  unsigned char savedFlag = 0;
  bool localizationActive =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x44) != 0;
  if (localizationActive) {
    savedFlag = *(reinterpret_cast<unsigned char*>(g_pGameFlowState) + 0x68);
    *(reinterpret_cast<unsigned char*>(g_pGameFlowState) + 0x68) = 0;
  }
  node->RefreshTurnEventDialog();
  node->CallVoidSlotA0();
  node->Free();
  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x44) != 0) {
    *(reinterpret_cast<unsigned char*>(g_pGameFlowState) + 0x68) = savedFlag;
  }
}

// FUNCTION: IMPERIALISM 0x005d5960
int TViewMgr::ClassifyTurnStateForOverlayMode() {
  switch (*reinterpret_cast<short*>(reinterpret_cast<char*>(g_pLocalizationTable) + 8)) {
  case 6:
  case 0xc:
  case 0xe:
  case 0xf:
  case 100:
  case 0x66:
  case 0x67:
  case 0x68:
    return 0;
  case 10:
  case 0xd:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x19:
  case 0x65:
    return 1;
  default:
    return 2;
  }
}

// FUNCTION: IMPERIALISM 0x005d6480
void TViewMgr::BuildAndShowTurnOverlayByMode(CString param_1, TToolBarClusterVtbl** param_2) {
  // TODO(batch2): port turn-overlay builder (g_pLocalizationTable vtable + CString work).
  (void)param_1;
  (void)param_2;
}

// FUNCTION: IMPERIALISM 0x005d69b0
void TViewMgr::ComputeTurnEventDialogPlacementByCode(TView* dialogView, POINT* outPlacement) {
  MainViewHostContext* host = *reinterpret_cast<MainViewHostContext**>(kAddrMainViewHostPtr);
  RECT mainBounds;
  host->mainView->QueryBounds(&mainBounds);
  (void)mainBounds; // original makes the call but discards the result

  char* afxWindow = reinterpret_cast<char*>(InvokeAfxThreadVslot7CAndGetValueAtOffset98());
  RECT clientRect;
  GetClientRect(*reinterpret_cast<HWND*>(afxWindow + 0x1c), &clientRect);

  RECT dialogBounds;
  dialogView->QueryBounds(&dialogBounds);
  int dlgWidth = dialogBounds.right - dialogBounds.left;
  int dlgHeight = dialogBounds.bottom - dialogBounds.top;

  // Center the dialog inside a per-event "design" rectangle, offset by the host
  // client origin. Most turn-event codes use the default bucket; a handful pick
  // the wider/taller special buckets.
  int designWidth = 0x276;
  int designHeight = 0x1d1;
  int margin = 0x1e;
  short code = this->currentTurnEventCode;
  if (code == 0x3b8 || code == 0x7dd) {
    designWidth = 0x200;
    designHeight = 0x1c0;
    margin = 0x16;
  } else if ((code >= 0x7d8 && code <= 0x7db) || code == 0x7de || code == 0x898 || code == 0xf3c ||
             code == 0xed8 || code == 0x2134 || code == 0x2260) {
    designHeight = 0x1c0;
  }

  outPlacement->x = (designWidth - dlgWidth) / 2 + clientRect.left + 5;
  outPlacement->y = (designHeight - dlgHeight) / 2 + clientRect.top + margin;
}

// FUNCTION: IMPERIALISM 0x005d6b70
void TViewMgr::RefreshMainViewNationIndicatorForCurrentTurnEvent() {
  MainViewHostContext* host = *reinterpret_cast<MainViewHostContext**>(kAddrMainViewHostPtr);
  TView* mainView = host->mainView;
  if (mainView == nullptr) {
    return;
  }
  // Turn-event 0x7DD targets the 'trb1' toolbar tag; everything else the 'tool' tag.
  TControl* control;
  if (this->currentTurnEventCode == 0x7dd) {
    control = mainView->ResolveControlByTag(0x74627231);
  } else {
    control = mainView->ResolveControlByTag(0x746f6f6c);
  }
  if (control != nullptr) {
    static_cast<TToolBarCluster*>(control)->UpdateControlTagTreaTextFromNationAndMapContext(
        reinterpret_cast<UiRuntimeContext*>(g_pLocalizationTable)->GetActiveNationId());
  }
}

// FUNCTION: IMPERIALISM 0x005dcaa0
void TViewMgr::HandleTurnEventVtableSlot2CInitializeHotKeyDialog() {
  // TODO(batch2): port hotkey-dialog init (CDialog + SEH + raw vtable).
}
