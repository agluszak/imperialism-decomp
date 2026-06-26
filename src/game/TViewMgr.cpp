#include "game/TViewMgr.h"
#include "game/TAssetMgr.h"
#include "game/TToolBarCluster.h" // pulls TView/TControl/TCluster chain for main-view dispatch
#include "game/TViewMgr.h"
#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/TCivToolbar.h"
#include "game/diplomacy_globals.h"  // g_pGameFlowState, g_pLocalizationTable
#include "game/TGlobalMapState.h"
#include "game/turn_flow_cooldown.h" // IsTurnCooldownCounterActiveOrResetFlag
#include "game/ui_invalidation_guard.h"
#include "game/turn_event_packets.h"

#include <new>

// GLOBAL: IMPERIALISM 0x6a21bc
TViewMgr* g_pUiRuntimeContext = 0;

// TSimMgr global instance @ 0x6a20f8 (a.k.a. g_pLocalizationTable / turn-state
// manager). Included via diplomacy_globals.h.

// Application/document root pointer @ 0x6a2158; its +0x04 field holds the active main
// TView used as the dispatch root for turn-event UI refreshes.
namespace {
struct MainViewHostContext {
  void* field0;    // +0x00
  TView* mainView; // +0x04
};
const unsigned int kAddrMainViewHostPtr = 0x006a2158;
} // namespace

#include "game/startup_helpers.h"

// Free-function thunks reached through the ILT jump table; declared in the generic
// repo form and invoked through typed __cdecl casts at the callsites.
undefined4 LoadTurnEventCursorByResourceIdOffset1000(void);
undefined4 SetQuickDrawFillColorFromPaletteIndex(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
// ILT thunk (generic form per repo policy; typed cast applied at the callsite).
undefined4 thunk_DispatchLocalizedUiMessageWithTemplateA13A0(void);
undefined4 FormatOverlayTerrainLabelText(void);
undefined4 LoadNationDisplayNameSharedRefFromField8(void);
undefined4 InitializeHotKeyDialogTemplateA1WithTripleTextState(void);
undefined4 RunNationInfoModalAndReturnNonCancel(void);
undefined4 NoOpUiRuntimeCallback_005db2f0(void);
undefined4 NoOpRuntimeCallback_005d5d10(void);
undefined4 DoModal_6051b9(void);
undefined4 scanBracketExpressions(void);

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
const unsigned int kAddrHotKeyDialogTemplate = 0x00698b1a;
const unsigned int kAddrHotKeyDialogTemplateEnd = 0x00698b52;
const unsigned int kAddrEmptyString = 0x0066f050;
const unsigned int kAddrLocalizedMessageTemplate = 0x006a13a0;
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
  this->mapUberPictureF0 = 0;
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
  this->mapUberPictureF0 = 0;
}


// FUNCTION: IMPERIALISM 0x005d5250
void TViewMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
}

short TViewMgr::GetActiveNationId(void) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(this) + 0x2e);
}

// FUNCTION: IMPERIALISM 0x005d5270
int TViewMgr::MapTurnEventCodeToPaletteIndex(int eventCode) {
  if (200 < eventCode) {
    if (eventCode < 0x2b68) {
      if (eventCode == 0x2b67) {
        return 0;
      }
      switch (eventCode) {
      case 0xc9:
        goto case_33;
      case 0xca:
        return 0x30;
      case 0xcb:
        goto case_6;
      case 0xcc:
        goto case_3b;
      case 0xcd:
        return 0x24;
      case 0xce:
        return 0x26;
      case 0xcf:
        goto case_34;
      case 0xd0:
        return 0x14;
      }
    } else {
      switch (eventCode) {
      case 0x2b68:
        return 0x13;
      case 0x2b69:
        return 0xcb;
      case 0x2b6a:
        return 0x5c;
      case 0x2b6b:
        return 0xd2;
      case 0x2b6c:
        return 0x28;
      case 0x2b6d:
        return 1;
      }
    }
    return 0xff;
  }
  if (eventCode != 200) {
    switch (eventCode) {
    case 0:
      return 0x16;
    case 1:
      return 0x2a;
    case 2:
    case 0x40:
      return 0x22;
    case 3:
    case 0x3c:
    case 0x4e:
      return 0x1c;
    case 4:
      return 0x2b;
    case 5:
      return 0x1e;
    case 6:
case_6:
      return 0x2e;
    case 7:
    case 0x35:
      return 10;
    case 8:
    case 0x3d:
      return 0xb;
    case 9:
      return 0xd;
    case 10:
    case 0x43:
      return 0x29;
    case 0xb:
      return 0xde;
    case 0xc:
    case 0x47:
      return 0xdf;
    case 0xd:
    case 0x49:
      return 0xfa;
    case 0xe:
    case 0x38:
      return 0x2c;
    case 0xf:
    case 0x4a:
      return 0x31;
    case 0x10:
      return 0x33;
    case 0x11:
      return 0x41;
    case 0x12:
      return 0x48;
    case 0x13:
      return 0xd0;
    case 0x14:
      return 0xcd;
    case 0x15:
      return 0xce;
    case 0x16:
      return 0xcf;
    default:
      return 0xff;
    case 0x25:
    case 0x3f:
      break;
    case 0x32:
      return 0x1a;
    case 0x33:
case_33:
      return 0x2d;
    case 0x34:
case_34:
      return 0x18;
    case 0x37:
      return 0xbd;
    case 0x3a:
      return 0xc6;
    case 0x3b:
case_3b:
      return 0x27;
    case 0x3e:
      return 0x15;
    case 0x41:
      return 0x1b;
    case 0x42:
      return 0x21;
    case 0x44:
      return 0x17;
    case 0x45:
      return 0x5f;
    case 0x46:
      return 0xbe;
    case 0x48:
      return 100;
    case 0x4b:
      return 0x66;
    case 0x4c:
      return 0x89;
    case 0x4d:
      return 0xad;
    case 0x4f:
      return 0xe7;
    case 0x50:
      return 0xe6;
    case 0x51:
      return 0xf6;
    case 0x52:
      return 0xc;
    case 0x53:
      return 0xef;
    case 0x54:
      return 0xf9;
    }
  }
  return 0x20;
}


// FUNCTION: IMPERIALISM 0x005d5750
void TViewMgr::ApplyTurnEventPaletteColorByEventCode(int eventCode) {
  int paletteIndex = this->MapTurnEventCodeToPaletteIndex(eventCode);
  reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColorFromPaletteIndex)(paletteIndex);
}


// FUNCTION: IMPERIALISM 0x005d5780
void TViewMgr::UpdatePaletteIndexFromTurnEventCode(int eventCode) {
  int paletteIndex = this->MapTurnEventCodeToPaletteIndex(eventCode);
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
        TemporarilyClearAndRestoreUiInvalidationFlag)(
        reinterpret_cast<const char*>(kAddrStrSourceFile), 0x223);
  }
  node->ShowTurnEventDialog(1);
  if (node->ResolveControlByTag(0x444c4f47) == nullptr) { // 'GOLD'
    MessageBoxA(nullptr, reinterpret_cast<const char*>(kAddrStrNilPointer),
                reinterpret_cast<const char*>(kAddrStrFailure), 0x30);
    reinterpret_cast<void(__cdecl*)(const char*, int)>(
        TemporarilyClearAndRestoreUiInvalidationFlag)(
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


// FUNCTION: IMPERIALISM 0x005d5a70
undefined4 TViewMgr::RunControlStringProviderAndDispatchLocalizedMessage(CString* messageString) {
  int overlayMode = this->ClassifyTurnStateForOverlayMode();
  CString stackMessage;
  ::new ((void*)&stackMessage) CString(*messageString);
  return this->DispatchLocalizedUiMessageWithTemplateA13A0(overlayMode, &stackMessage);
}

// FUNCTION: IMPERIALISM 0x005d5b00
undefined1 TViewMgr::DispatchLocalizedUiMessageWithTemplateA13A0(int overlayMode,
                                                                  CString* messageCString) {
  CString messageLocal;
  ::new ((void*)&messageLocal) CString(*messageCString);
  CString formatArg;
  formatArg = reinterpret_cast<const char*>(kAddrLocalizedMessageTemplate);
  (void)overlayMode;
  (void)formatArg;
  (void)messageLocal;
  return this->DispatchLocalizedUiMessageWithTemplate(3);
}

// FUNCTION: IMPERIALISM 0x005d5c40
undefined1 TViewMgr::DispatchLocalizedUiMessageWithTemplate(int templateKind) {
  (void)templateKind;
  return 0;
}

static void CopyHotKeyDialogTemplateToBuffer(int buffer) {
  const unsigned short* src = reinterpret_cast<const unsigned short*>(kAddrHotKeyDialogTemplate);
  const unsigned short* srcEnd =
      reinterpret_cast<const unsigned short*>(kAddrHotKeyDialogTemplateEnd);
  unsigned short* dst = reinterpret_cast<unsigned short*>(buffer + 0x10);
  while (src < srcEnd) {
    dst[-7] = src[-1];
    dst[0] = src[0];
    dst[7] = src[1];
    dst[0xe] = src[2];
    ++dst;
    src += 4;
  }
}

// FUNCTION: IMPERIALISM 0x005d6480
void TViewMgr::BuildAndShowTurnOverlayByMode(int overlayMode, int contextArg) {
  CString formattedText;
  CString templateText;
  CString scratchA;
  CString scratchB;
  short resourceId = static_cast<short>(overlayMode);

  switch (overlayMode) {
  case 0:
    g_pLocalizationTable->GetString(0, 0, &scratchA);
    g_pLocalizationTable->GetString(0x2716, 0, &templateText);
    reinterpret_cast<void(__stdcall*)(void*, void*, char*)>(scanBracketExpressions)(
        g_pLocalizationTable, &formattedText,
        const_cast<char*>(static_cast<LPCSTR>(templateText)));
    if (contextArg == 8) {
      resourceId = 0x2515;
    } else if (contextArg == 9) {
      resourceId = 0x2516;
    } else {
      resourceId = static_cast<short>((-static_cast<int>(contextArg != 0xc) & 0xfff1) + 0x2517);
    }
    break;
  case 1: {
    g_pLocalizationTable->GetString(0, 0, &templateText);
    short nationId = g_pUiRuntimeContext->GetActiveNationId();
    short cap = g_pCityOrderCapabilityState->nationCapRows1e8[nationId].cap;
    if (cap == 0x1c) {
      resourceId = 0x2518;
    } else {
      resourceId = static_cast<short>((-static_cast<int>(cap != 0x1d) & 0xfff0) + 0x2519);
    }
    break;
  }
  case 2:
    g_pLocalizationTable->GetString(0, 0, &templateText);
    resourceId = 0x250a;
    break;
  case 3:
  case 4:
    g_pGlobalMapState->AssignSharedStringFromIndexedA8EntryNameField(contextArg, &formattedText);
    g_pLocalizationTable->GetString(0, 0, &templateText);
    reinterpret_cast<void(__stdcall*)(void*, void*, char*)>(scanBracketExpressions)(
        g_pLocalizationTable, &formattedText,
        const_cast<char*>(static_cast<LPCSTR>(templateText)));
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 5:
  case 0xc:
    g_pLocalizationTable->GetString(0, 0, &templateText);
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 6:
    reinterpret_cast<void(__cdecl*)(void)>(LoadNationDisplayNameSharedRefFromField8)();
    g_pLocalizationTable->GetString(0, 0, &templateText);
    reinterpret_cast<void(__stdcall*)(void*, void*, char*)>(scanBracketExpressions)(
        g_pLocalizationTable, &formattedText,
        const_cast<char*>(static_cast<LPCSTR>(templateText)));
    resourceId = 0x250e;
    break;
  case 7:
    g_pLocalizationTable->GetString(0, 0, &templateText);
    resourceId = static_cast<short>((-static_cast<int>(contextArg != -1) & 0xfff5) + 0x251a);
    break;
  case 8:
    g_pLocalizationTable->GetString(0, 0, &templateText);
    resourceId = 0x2510;
    break;
  case 9:
  case 0xb:
    g_pLocalizationTable->GetString(0, 0, &templateText);
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 0xa:
    reinterpret_cast<void(__cdecl*)(void)>(FormatOverlayTerrainLabelText)();
    g_pLocalizationTable->GetString(0, 0, &templateText);
    reinterpret_cast<void(__stdcall*)(void*, void*, char*)>(scanBracketExpressions)(
        g_pLocalizationTable, &formattedText,
        const_cast<char*>(static_cast<LPCSTR>(templateText)));
    resourceId = 0x2512;
    break;
  default:
    resourceId = static_cast<short>(contextArg);
    break;
  }

  int resourceIdSlot = resourceId;
  int modalContext = -1000;
  (void)modalContext;
  reinterpret_cast<void(__cdecl*)(void)>(NoOpUiRuntimeCallback_005db2f0)();
  reinterpret_cast<void(__cdecl*)(void)>(NoOpRuntimeCallback_005d5d10)();
  CString emptyLabel;
  emptyLabel = reinterpret_cast<const char*>(kAddrEmptyString);
  (void)emptyLabel;
  volatile int* resourcePtr = &resourceIdSlot;
  (void)resourcePtr;
  reinterpret_cast<void(__cdecl*)(void)>(RunNationInfoModalAndReturnNonCancel)();
}


// FUNCTION: IMPERIALISM 0x005d69b0
void TViewMgr::ComputeTurnEventDialogPlacementByCode(TView* dialogView, POINT* outPlacement) {
  MainViewHostContext* host = *reinterpret_cast<MainViewHostContext**>(kAddrMainViewHostPtr);
  RECT mainBounds;
  host->mainView->QueryBounds(&mainBounds);
  (void)mainBounds; // original makes the call but discards the result

  char* afxWindow = reinterpret_cast<char*>(GetMainViewHostFromActiveThread());
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
        g_pUiRuntimeContext->GetActiveNationId());
  }
}


// FUNCTION: IMPERIALISM 0x005dcaa0
void TViewMgr::HandleTurnEventVtableSlot2CInitializeHotKeyDialog() {
  CDialog dialog;
  reinterpret_cast<void(__cdecl*)(void)>(InitializeHotKeyDialogTemplateA1WithTripleTextState)();

  char* buffer = new char[0x3e];
  if (buffer != 0) {
    CopyHotKeyDialogTemplateToBuffer(reinterpret_cast<int>(buffer));
    *reinterpret_cast<void**>(buffer + 0x118) = &dialog;

    int modalResult = reinterpret_cast<int(__cdecl*)(void)>(DoModal_6051b9)();
    if (modalResult != 0) {
      g_pLocalizationTable->CopyScenarioNationSetupIntoFlowState(reinterpret_cast<void*>(buffer));
    }
    delete[] buffer;
  }
}

void TViewMgr::DispatchTurnEventSlot4C(short eventCode, int payload) {
  (void)eventCode;
  (void)payload;
}

void TViewMgr::UiRuntimeSlot50() {}

short TViewMgr::QueryUiScreenModeSlot54() {
  return 0;
}

void TViewMgr::UiRuntimeSlot58() {}

void TViewMgr::UiRuntimeSlot5C() {}

void TViewMgr::UiRuntimeSlot60() {}

void TViewMgr::UiRuntimeSlot64() {}

void TViewMgr::ApplyUiRuntimeSlot68(int modeValue) {
  (void)modeValue;
}

void TViewMgr::UiRuntimeSlot6C() {}

void TViewMgr::UiRuntimeSlot70() {}

void TViewMgr::UiRuntimeSlot74() {}

void TViewMgr::UiRuntimeSlot78() {}

void TViewMgr::UiRuntimeSlot7C() {}

void TViewMgr::UiRuntimeSlot80() {}

void TViewMgr::UiRuntimeSlot84() {}

void TViewMgr::UiRuntimeSlot88() {}

void TViewMgr::UiRuntimeSlot8C() {}

char TViewMgr::RequestDiplomacyDecisionSlot90(int sourceNation, int targetNation, int proposalCode) {
  (void)sourceNation;
  (void)targetNation;
  (void)proposalCode;
  return 0;
}

char TViewMgr::RequestDecisionSlot94(int sourceNation, int arg1, int arg2, int promptCode) {
  (void)sourceNation;
  (void)arg1;
  (void)arg2;
  (void)promptCode;
  return 0;
}

void TViewMgr::DispatchDecisionSlot98(int sourceNation, int arg2, int arg3, int targetNation) {
  (void)sourceNation;
  (void)arg2;
  (void)arg3;
  (void)targetNation;
}

void TViewMgr::UiRuntimeSlot9C() {}

void TViewMgr::UiRuntimeSlotA0() {}

void TViewMgr::UiRuntimeSlotA4() {}

void TViewMgr::UiRuntimeSlotA8() {}

void TViewMgr::RefreshCityProductionUiSlotAc() {}

void TViewMgr::UiRuntimeSlotB0() {}

void TViewMgr::UiRuntimeSlotB4() {}

void TViewMgr::UiRuntimeSlotB8() {}

void TViewMgr::UiRuntimeSlotBC() {}

void TViewMgr::UiRuntimeSlotC0() {}

void TViewMgr::UiRuntimeSlotC4() {}

void TViewMgr::UiRuntimeSlotC8() {}

void TViewMgr::UiRuntimeSlotCC() {}

void TViewMgr::UiRuntimeSlotD0() {}

void TViewMgr::UiRuntimeSlotD4() {}

void TViewMgr::UiRuntimeSlotD8() {}

int TViewMgr::ShowConstructionOptionsDialog() {
  return 0;
}

