#include "game/TViewMgr.h"

#include "game/ImperialismApp.h"
#include "game/TAssetMgr.h"
#include "game/TSoundPlayer.h"        // g_pSfxPlaybackSystem
#include "game/TMacViewMgr.h"         // g_pStrategicMapViewSystem
#include "game/TIncludeView.h"        // turn-event UI entry packet ('Incl')
#include "game/CWMgrIterator.h"       // window-registry traversal for the full (code-0) refresh
#include "game/quickdraw_rendering.h" // SetQuickDrawFillColor / SetQuickDrawStrokeColor
#include "game/TToolBarCluster.h"     // pulls TView/TControl/TCluster chain for main-view dispatch

#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/TCivToolbar.h"
#include "game/global_data_tables.h" // g_pGameFlowState, g_pLocalizationTable, g_apNationStates
#include "game/TGreatPower.h"
#include "game/TGlobalMapState.h"
#include "game/TDisplayMgr.h" // g_pDisplayMgr, g_szUiNilPointerMessage, g_szUiFailureMessage
#include "game/THelpMgr.h"
#include "game/TWindow.h"
#include "game/ui_control_tags.h"
#include "game/TInfoBarText.h"
#include "game/TCouncilTickerAnimation.h"
#include "game/TToolBarCluster.h"
#include "game/TPicture.h"
#include "game/turn_flow_cooldown.h" // IsTurnCooldownCounterActiveOrResetFlag
#include "game/ui_invalidation_guard.h"
#include "game/TMultiplayerMgr.h"
#include "game/TMilitaryUnitOrderState.h" // g_szEmptyString
#include "game/localization_text_helpers.h"
#include "game/TCluster.h"
#include "game/TCursorControlPanel.h"
#include "game/TDiplomacyMapView.h"

char IsNationSlotEligibleForEventProcessing(short nationSlot);

undefined4 QueueDeferredUiEventPacket(void);
undefined4 ShowDialogTemplateE0ModalAndReleaseCapture(void);
undefined4 HandleTurnEvent8FC_RebuildPageTabsAndTitles(void);

#include <new>

// TSimMgr global instance @ 0x6a20f8 (a.k.a. g_pLocalizationTable / turn-state
// manager). Included via global_data_tables.h.

// The display/GWorld manager (g_pDisplayMgr @ 0x6a2158); its activeDialog (+0x04) field
// holds the active main TView used as the dispatch root for turn-event UI refreshes.

#include "game/startup_helpers.h"
#include "game/CIncludeView.h"

// Free-function thunks reached through the ILT jump table; declared in the generic
// repo form and invoked through typed __cdecl casts at the callsites.
undefined4 SetQuickDrawFillColorFromPaletteIndex(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);
// ILT thunk (generic form per repo policy; typed cast applied at the callsite).
undefined4 thunk_DispatchLocalizedUiMessageWithTemplateA13A0(void);
undefined4 FormatOverlayTerrainLabelText(void);
undefined4 InitializeHotKeyDialogTemplateA1WithTripleTextState(void);
undefined4 RunNationInfoModalAndReturnNonCancel(void);
undefined4 NoOpUiRuntimeCallback_005db2f0(void);
undefined4 NoOpRuntimeCallback_005d5d10(void);
undefined4 DoModal_6051b9(void);

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
const unsigned int kAddrStrSourceFile = 0x0069b6bc;
const unsigned int kAddrHotKeyDialogTemplate = 0x00698b1a;
const unsigned int kAddrHotKeyDialogTemplateEnd = 0x00698b52;
const unsigned int kAddrLocalizedMessageTemplate = 0x006a13a0;
} // namespace

namespace {
const unsigned int kAddrClassDescTViewMgr = 0x0066f0b8;
const unsigned int kAddrTurnStateSeedLo = 0x006a5b58;
const unsigned int kAddrTurnStateSeedHi = 0x006a5b5c;
} // namespace

extern "C" const char s_TurnEventCursorNameFormat_0069B6B4[];

HCURSOR LoadTurnEventCursorByResourceIdOffset1000(int cursorResourceId);
IMPLEMENT_DYNCREATE(TViewMgr, TObject)

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
    this->cursorTable[i] = LoadTurnEventCursorByResourceIdOffset1000(i + 1000);
  }
}

// FUNCTION: IMPERIALISM 0x005d5140
HCURSOR LoadTurnEventCursorByResourceIdOffset1000(int cursorResourceId) {
  CString cursorName;
  cursorName.Format(s_TurnEventCursorNameFormat_0069B6B4, cursorResourceId);
  AFX_MODULE_STATE* moduleState = AfxGetModuleState();
  return LoadCursorA(moduleState->m_hCurrentInstanceHandle, cursorName);
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
  TurnEventDialogNode* node = static_cast<TurnEventDialogNode*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x7e5));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    reinterpret_cast<void(__cdecl*)(const char*, int)>(
        TemporarilyClearAndRestoreUiInvalidationFlag)(
        reinterpret_cast<const char*>(kAddrStrSourceFile), 0x223);
  }
  node->ShowTurnEventDialog(1);
  if (node->ResolveControlByTag(0x444c4f47) == nullptr) { // 'GOLD'
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
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
    savedFlag = g_pGameFlowState->processPrimaryEventQueue;
    g_pGameFlowState->processPrimaryEventQueue = 0;
  }
  node->RefreshTurnEventDialog();
  node->CallVoidSlotA0();
  node->Free();
  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(g_pLocalizationTable) + 0x44) != 0) {
    g_pGameFlowState->processPrimaryEventQueue = savedFlag;
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
    scanBracketExpressions(g_pLocalizationTable, &formattedText, static_cast<LPCSTR>(templateText));
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
    short nationId = g_pLocalizationTable->GetActiveNationId();
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
    scanBracketExpressions(g_pLocalizationTable, &formattedText, static_cast<LPCSTR>(templateText));
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 5:
  case 0xc:
    g_pLocalizationTable->GetString(0, 0, &templateText);
    resourceId = static_cast<short>(overlayMode + 0x2508);
    break;
  case 6: {
    TGreatPower* nation = g_apNationStates[g_pLocalizationTable->GetActiveNationId()];
    if (nation != nullptr) {
      nation->LoadNationDisplayNameSharedRefFromField8(&formattedText);
    }
    g_pLocalizationTable->GetString(0, 0, &templateText);
    scanBracketExpressions(g_pLocalizationTable, &formattedText, static_cast<LPCSTR>(templateText));
    resourceId = 0x250e;
    break;
  }
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
    scanBracketExpressions(g_pLocalizationTable, &formattedText, static_cast<LPCSTR>(templateText));
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
  CString emptyLabel(g_szEmptyString);
  (void)emptyLabel;
  volatile int* resourcePtr = &resourceIdSlot;
  (void)resourcePtr;
  reinterpret_cast<void(__cdecl*)(void)>(RunNationInfoModalAndReturnNonCancel)();
}

// FUNCTION: IMPERIALISM 0x005d69b0
void TViewMgr::ComputeTurnEventDialogPlacementByCode(TView* dialogView, POINT* outPlacement) {
  RECT mainBounds;
  g_pDisplayMgr->activeDialog->QueryBounds(&mainBounds);
  (void)mainBounds; // original makes the call but discards the result

  CIncludeView* mainView = GetMainViewHostFromActiveThread();
  RECT clientRect;
  GetClientRect(mainView->m_hWnd, &clientRect);

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
  TView* mainView = g_pDisplayMgr->activeDialog;
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
        g_pLocalizationTable->GetActiveNationId());
  }
}

// FUNCTION: IMPERIALISM 0x005d6bf0
void TViewMgr::AddPendingTurnOverlayCode(int modeValue) {
  fieldEc = static_cast<short>(fieldEc + static_cast<short>(modeValue));
}

// FUNCTION: IMPERIALISM 0x005d6c10
short TViewMgr::GetPendingTurnOverlayCode() {
  return fieldEc;
}

// FUNCTION: IMPERIALISM 0x005d6c30
void TViewMgr::UiRuntimeSlot58() {
  static const char kStatusIconTagBytes[] =
      " 0sr 1sr 2sr 3sr 4sr 5sr 6sr 0am 1am 2am 3am 4am 5am 0dg 1dg 2dg 3dg";
  TView* mainView = g_pDisplayMgr->activeDialog;
  const short nationId = this->pad06;
  for (short iconIndex = 0; iconIndex < 0x12; ++iconIndex) {
    const unsigned int tag =
        *reinterpret_cast<const unsigned int*>(kStatusIconTagBytes + iconIndex * 4);
    TControl* control = mainView->ResolveControlByTag(tag);
    if (control != nullptr) {
      control->AssertValid();
      g_pStrategicMapViewSystem->OrphanCallChain_C4_I35_0050bbc0(reinterpret_cast<int*>(control),
                                                                 iconIndex, nationId);
    }
  }
  TGreatPower* nation = g_apNationStates[nationId];
  if (nation != nullptr) {
    nation->SnapshotDiplomacyState1c6Into250();
  }
}

// FUNCTION: IMPERIALISM 0x005d6e30
void TViewMgr::UiRuntimeSlot8C(int arg) {
  (void)arg;
}

// FUNCTION: IMPERIALISM 0x005d7190
void TViewMgr::UiRuntimeSlotD4(int arg) {
  (void)arg;
}

// Clears style bit 0x02000000 on the main view's host window.
static void ModifyMainViewChildWindowStyleClear02000000(TView* mainView) {
  if (mainView->nativeWindow50 != nullptr) {
    mainView->nativeWindow50->ModifyStyle(0, 0x02000000);
  }
}

namespace turn_event_ui_refresh {

TView* ActiveMainView() {
  return g_pDisplayMgr->activeDialog;
}

TControl* ResolveMainTaggedControl(unsigned int controlTag) {
  TView* mainView = ActiveMainView();
  if (mainView == nullptr) {
    return nullptr;
  }
  return mainView->ResolveControlByTag(controlTag);
}

void BindCursorPanelAndSetTurnEventCodeRange() {
  TControl* cursor = ResolveMainTaggedControl(kControlTagCrus);
  g_pCursorControlPanel = static_cast<TCursorControlPanel*>(cursor);
  if (cursor != nullptr) {
    cursor->AssertValid();
    static_cast<TInfoBarText*>(cursor)->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
  }
}

void RefreshMainCouncilTickerPanel() {
  TControl* mainPanel = ResolveMainTaggedControl(kControlTagMain);
  if (mainPanel != nullptr) {
    mainPanel->AssertValid();
    TCouncilTickerAnimation* councilPanel =
        static_cast<TCouncilTickerAnimation*>(static_cast<void*>(mainPanel));
    councilPanel->InitializeDiplomacyCouncilViewControlsAndTicker();
  }
}

void RefreshToolBarClusterByTag(unsigned int controlTag) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(control);
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(
      g_pLocalizationTable->GetActiveNationId());
  toolbar->RefreshTurnOrderStatusPanelTextsAndControls();
}

void RefreshOrderStatusPicture(unsigned int controlTag, unsigned int flagMask,
                               short pictureWhenFlagSet, short pictureWhenFlagClear) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  const short pictureId = g_pLocalizationTable->TestTurnFlowStatusFlagMask(flagMask)
                              ? pictureWhenFlagSet
                              : pictureWhenFlagClear;
  static_cast<TPicture*>(control)->SetPictureResourceIdAndRefresh(pictureId, true);
}

void RefreshTradClusterPictureAndHintText() {
  TControl* tradControl = ResolveMainTaggedControl(kControlTagTrad);
  if (tradControl == nullptr) {
    return;
  }
  tradControl->AssertValid();
  TToolBarCluster* tradCluster = static_cast<TToolBarCluster*>(tradControl);
  const short pictureId = static_cast<short>(tradCluster->field84 + 1);
  static_cast<TPicture*>(tradControl)->SetPictureResourceIdAndRefresh(pictureId, false);
  tradControl->SetState(0, 0);

  CString hintText;
  g_pLocalizationTable->GetString(0x2730, 0, &hintText);
  tradControl->EnableAndProcessFlag(hintText);
}

void RefreshTaggedControlWithLocalizedString(unsigned int controlTag, short stringCode,
                                             short stringIndex) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  CString localizedText;
  g_pLocalizationTable->GetString(stringCode, stringIndex, &localizedText);
  control->EnableAndProcessFlag(localizedText);
}

void ApplyThemeToTaggedTextControl(unsigned int controlTag, int styleWidth, int stylePrimary,
                                   int styleSecondary) {
  TControl* control = ResolveMainTaggedControl(controlTag);
  if (control == nullptr) {
    return;
  }
  control->AssertValid();
  TControlPictureRectState styleDescriptor;
  styleDescriptor.mode = 0;
  styleDescriptor.flag2 = 0;
  styleDescriptor.pointSize = 0;
  styleDescriptor.styleRef6 = 0;
  BuildUiTextStyleDescriptor(&styleDescriptor, 0, styleWidth, styleSecondary);
  control->SetCityProductionDialogPictureRectAndMaybeRefresh(&styleDescriptor, 0);
  (void)stylePrimary;
}

void RefreshQuerControlLayoutAndClearText() {
  TControl* querControl = ResolveMainTaggedControl(kControlTagQuer);
  if (querControl == nullptr) {
    return;
  }
  querControl->AssertValid();
  int layoutCaptureBuffer = 0;
  querControl->CaptureLayoutF0(&layoutCaptureBuffer, 0);
  querControl->EnableAndProcessFlag(g_szEmptyString);
}

} // namespace turn_event_ui_refresh

namespace {
void DispatchPostTurnStateUpdatesTail() {
  if (g_pHelpMgr == nullptr) {
    return;
  }
  if (IsTurnCooldownCounterActiveOrResetFlag() != 0) {
    return;
  }
  g_pHelpMgr->HandlePostDispatchTurnStateEventUpdates();
  g_pHelpMgr->HandlePendingEventActivationByCode(g_pUiRuntimeContext->currentTurnEventCode);
  g_pHelpMgr->HandlePostPendingEventActivationNoOp(g_pUiRuntimeContext->currentTurnEventCode);
}
} // namespace

// FUNCTION: IMPERIALISM 0x005d7240
void TViewMgr::DispatchTurnEventSlot4C(short eventCode, int payload) {
  TView* mainView = g_pDisplayMgr->activeDialog;
  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0xffffff);

  const short newCode = eventCode;
  const short secondary = static_cast<short>(payload);

  // Sound cue when the turn-flow mode is in the 0x67..0x6a band and the code changed.
  if (newCode != this->currentTurnEventCode) {
    switch (static_cast<short>(g_pLocalizationTable->mode)) {
    case 0x67:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5b);
      break;
    case 0x68:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5c);
      break;
    case 0x69:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5e);
      break;
    case 0x6a:
      g_pSfxPlaybackSystem->PlaySoundEffect(0x1b5d);
      break;
    }
  }

  // Teardown hook for the code currently displayed.
  const int curCode = this->currentTurnEventCode;
  if (curCode < 0x2135) {
    if (curCode == 0x2134) {
      ModifyMainViewChildWindowStyleClear02000000(mainView);
    } else {
      switch (curCode) {
      case 0x7d9:
      case 0x7da:
        this->UiRuntimeSlot58();
        break;
      case 0x7db:
        g_pStrategicMapViewSystem->OrphanCallChain_C1_I10_0050d920();
        break;
      case 0x7dd:
        this->mapUberPictureF0 = 0;
        break;
      }
    }
  }

  // Code 0 = rebuild every registered UI window node.
  if (newCode == 0) {
    *reinterpret_cast<unsigned char*>(reinterpret_cast<char*>(g_pGlobalUiRootController) + 0x4c) =
        0;
    this->currentTurnEventCode = 0;
    *reinterpret_cast<short*>(reinterpret_cast<char*>(g_pDisplayMgr) + 0x1c) = 0;
    mainView->CallVoidSlotA0();
    CWMgrIterator iter;
    iter.Reset(1);
    TWindow* window = static_cast<TWindow*>(iter.FirstWindow());
    while (iter.More() != 0) {
      const unsigned int tag = static_cast<unsigned int>(window->controlTag);
      if (tag == kControlTagWpam || tag == kControlTagWnrt) {
        window->OrphanCallChain_C2_I10_0048e120();
      }
      window = static_cast<TWindow*>(iter.NextWindow());
    }
    return;
  }

  // Same-code refresh: refresh the main view, then run the per-code hook.
  if (newCode == this->currentTurnEventCode) {
    if (secondary != -1) {
      this->pad06 = secondary;
    }
    if (newCode == 0x5e4) {
      QueueDeferredUiEventPacket(); // (mainView, 0x29a) — args deferred pending port
    } else if (newCode == 0x547) {
      mainView->RefreshControl();
      g_pCursorControlPanel->AssertValid();
    } else if (newCode == 0x8fc) {
      mainView->RefreshControl();
      HandleTurnEvent8FC_RebuildPageTabsAndTitles();
    } else if (newCode == 0x7d8) {
      if (static_cast<short>(g_pLocalizationTable->mode) == 0x68) {
        mainView->RefreshControl();
        this->UiRuntimeSlot6C();
      }
    } else if (newCode == 0x7d9 || newCode == 0x7da) {
      mainView->RefreshControl();
      this->UiRuntimeSlot5C();
    } else if (newCode == 0x7db) {
      mainView->RefreshControl();
      this->UiRuntimeSlotA8();
    } else if (newCode == 0x7dd) {
      mainView->RefreshControl();
      this->UiRuntimeSlotBC();
    } else if (newCode == 0x7de) {
      mainView->RefreshControl();
      this->UiRuntimeSlot84();
    } else if (newCode == 0x2103) {
      this->UiRuntimeSlot9C();
    } else if (newCode == 0x2260) {
      mainView->RefreshControl();
      this->UiRuntimeSlot64();
    }
    DispatchPostTurnStateUpdatesTail();
    return;
  }

  // Cross-code path: tear down the previous dialog, build the new turn-event UI packet.
  g_pUiViewManager->NoOpRuntimeUiCallback_005df780(0);
  mainView->DispatchSlot9CToLinkedChildren();
  if (this->field10 != 0) {
    ShowDialogTemplateE0ModalAndReleaseCapture();
    this->field10 = 0;
  }
  TControl* inclControl = mainView->ResolveControlByTag(0x496e636c); // 'Incl'
  if (inclControl != nullptr) {
    inclControl->AssertValid();
    inclControl->RefreshControl();
    inclControl->Free();
  }

  TIncludeView* packet = new TIncludeView();
  CString emptyText(g_szEmptyString);
  int anchorPoint[2] = {0, 0};
  packet->BuildTurnEventFactoryPacket(nullptr, mainView, newCode, anchorPoint, &emptyText, 1);
  packet->NoOpUiLifecycleHook(0);
  packet->controlTag = 0x496e636c; // 'Incl'
  packet->RefreshControl();
  g_pDisplayMgr->LoadMainViewClipSnapshotIntoQuickDrawState(static_cast<unsigned short>(newCode));
  if (this->field10 != 0) {
    ShowDialogTemplateE0ModalAndReleaseCapture();
    this->field10 = 0;
  }
  this->currentTurnEventCode = newCode;

  if (newCode > 0x3c0) {
    if (newCode < 0x5dd) {
      if (newCode == 0x5dc) {
        this->UiRuntimeSlotF8();
      } else if (newCode == 0x547) {
        this->UiRuntimeSlot50(static_cast<int>(newCode));
      }
    } else if (newCode < 0x7d9) {
      switch (newCode) {
      case 0x5dd:
        this->UiRuntimeSlotFC();
        break;
      case 0x5de:
        this->UiRuntimeSlot100();
        break;
      case 0x5df:
        this->UiRuntimeSlot104();
        break;
      case 0x5e0:
        this->UiRuntimeSlot108();
        break;
      case 0x7d8:
        this->UiRuntimeSlot6C();
        break;
      }
    } else if (newCode > 0x898) {
      if (newCode == 0xed8 || newCode == 0xf3c) {
        this->UiRuntimeSlotF4();
      } else if (newCode == 0x8fc) {
        HandleTurnEvent8FC_RebuildPageTabsAndTitles();
      } else if (newCode == 0x11f8) {
        this->UiRuntimeSlot110();
      } else if (newCode == 0xf3d) {
        this->UiRuntimeSlotA0();
      } else if (newCode == 0x2103) {
        this->UiRuntimeSlot64();
      } else if (newCode == 0x2134) {
        this->UiRuntimeSlot60();
      } else if (newCode == 0x2260) {
        this->UiRuntimeSlot9C();
      }
    } else if (newCode == 0x898) {
      this->UiRuntimeSlotBC();
    } else {
      switch (newCode) {
      case 0x7d9:
        this->UiRuntimeSlotBC();
        break;
      case 0x7da:
        this->UiRuntimeSlot5C();
        break;
      case 0x7db:
        this->UiRuntimeSlotA8();
        break;
      case 0x7dd:
        this->UiRuntimeSlot50(static_cast<int>(secondary));
        break;
      case 0x7de:
        this->UiRuntimeSlot84();
        break;
      case 0x7e0:
        this->UiRuntimeSlot50(static_cast<int>(secondary));
        break;
      }
    }
  } else if (newCode == 0x3c0) {
    this->UiRuntimeSlot10C();
  } else if (newCode == 0x3b8) {
    this->UiRuntimeSlotD0();
  }
  DispatchPostTurnStateUpdatesTail();
}

// FUNCTION: IMPERIALISM 0x005d7c40
void TViewMgr::UiRuntimeSlotA4(int payload, TEventHandler* waitTarget) {
  DispatchTurnEventSlot4C(0x3b8, payload);
  while (static_cast<short>(waitTarget->field14) == 0) {
    if (PumpUiMessagesAndBackgroundTasks(1) == 0) {
      PostWmCloseToMainThreadWindow();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005d7cb0
void TViewMgr::UiRuntimeSlotA8() {
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  TView* mainView = turn_event_ui_refresh::ActiveMainView();
  if (mainView == nullptr) {
    return;
  }

  TControl* cityControl = mainView->ResolveControlByTag(kControlTagCity);
  if (cityControl != nullptr) {
    cityControl->AssertValid();
    cityControl->SetState(0, 0);
    cityControl->SwitchActiveChildAndNotify(nullptr);
    cityControl->EnableAndProcessFlag(g_szEmptyString);
  }

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = mainView->ResolveControlByTag(kControlTagQuer);
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->EnableAndProcessFlag(g_szEmptyString);
  }
}

void TViewMgr::RefreshCityProductionUiSlotAc() {}

void TViewMgr::UiRuntimeSlotB0() {}

void TViewMgr::UiRuntimeSlotB4() {}

void TViewMgr::UiRuntimeSlotB8() {}

// FUNCTION: IMPERIALISM 0x005d7fc0
void TViewMgr::UiRuntimeSlot50(int payload) {
  (void)payload;
  TView* mainView = g_pDisplayMgr->activeDialog;
  TControl* cursor = mainView->ResolveControlByTag(kControlTagCrus);
  g_pCursorControlPanel = static_cast<TCursorControlPanel*>(cursor);
  cursor->AssertValid();
  static_cast<TInfoBarText*>(cursor)->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);
  TControl* mainPanel = mainView->ResolveControlByTag(kControlTagMain);
  mainPanel->AssertValid();
  static_cast<TCouncilTickerAnimation*>(static_cast<void*>(mainPanel))
      ->InitializeDiplomacyCouncilViewControlsAndTicker();
}

// FUNCTION: IMPERIALISM 0x005d8040
void TViewMgr::UiRuntimeSlot6C() {
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  TView* mainView = turn_event_ui_refresh::ActiveMainView();
  if (mainView == nullptr) {
    return;
  }

  TControl* diplControl = mainView->ResolveControlByTag(kControlTagDipl);
  if (diplControl != nullptr) {
    diplControl->AssertValid();
    diplControl->SetState(0, 0);
    diplControl->SwitchActiveChildAndNotify(nullptr);
    diplControl->EnableAndProcessFlag(g_szEmptyString);
  }

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = mainView->ResolveControlByTag(kControlTagQuer);
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->EnableAndProcessFlag(g_szEmptyString);
  }

  if (diplControl != nullptr) {
    diplControl->RefreshControl();
  }
}

void TViewMgr::UiRuntimeSlot70() {}

void TViewMgr::UiRuntimeSlot74() {}

void TViewMgr::UiRuntimeSlot78() {}

void TViewMgr::UiRuntimeSlot7C() {}

void TViewMgr::UiRuntimeSlot80() {}

// FUNCTION: IMPERIALISM 0x005d83b0
void TViewMgr::UiRuntimeSlot84() {
  turn_event_ui_refresh::RefreshMainCouncilTickerPanel();
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();

  TControl* tranControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagTran);
  if (tranControl != nullptr) {
    tranControl->AssertValid();
    tranControl->SetState(0, 0);
    tranControl->SwitchActiveChildAndNotify(nullptr);
    tranControl->EnableAndProcessFlag(g_szEmptyString);
  }

  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* querControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagQuer);
  if (querControl != nullptr) {
    querControl->AssertValid();
    querControl->EnableAndProcessFlag(g_szEmptyString);
  }
}

void TViewMgr::UiRuntimeSlot88() {}

char TViewMgr::RequestDiplomacyDecisionSlot90(int sourceNation, int targetNation,
                                              int proposalCode) {
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

// FUNCTION: IMPERIALISM 0x005d8dd0
void TViewMgr::UiRuntimeSlot5C() {
  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  turn_event_ui_refresh::RefreshTradClusterPictureAndHintText();
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagBpot);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagBpot, 0x2730, 0);

  TControl* textControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagText);
  if (textControl != nullptr) {
    textControl->AssertValid();
    textControl->EnableAndProcessFlag(g_szEmptyString);
  }

  const short activeNationId = g_pLocalizationTable->GetActiveNationId();
  g_apNationStates[activeNationId]->ReturnFalseNationStateCapabilityFlag9C();
  this->fieldEc = 0;
  for (short metricSlot = 0; metricSlot < 0x11; ++metricSlot) {
    if (g_apNationStates[activeNationId]->QueryNationMetricBySlot7C(metricSlot) == -1) {
      this->fieldEc = static_cast<short>(this->fieldEc + 1);
    }
  }

  turn_event_ui_refresh::ApplyThemeToTaggedTextControl(kControlTagText, 0xc, 0x2b67, 0x2b6c);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagText, 0x2730, 0);
  turn_event_ui_refresh::ApplyThemeToTaggedTextControl(kControlTagFood, 0xc, 0x2b67, 0x2b6c);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2731, 0);

  TControlPictureRectState foodStyle;
  foodStyle.mode = 0;
  foodStyle.flag2 = 0;
  foodStyle.pointSize = 0;
  foodStyle.styleRef6 = 0;
  BuildUiTextStyleDescriptor(&foodStyle, 0, 0xc, 0x2b6b);
  TControl* foodControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagFood);
  if (foodControl != nullptr) {
    foodControl->AssertValid();
    foodControl->SetCityProductionDialogPictureRectAndMaybeRefresh(&foodStyle, 0);
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
    foodControl->SetCityProductionDialogPictureRectAndMaybeRefresh(&foodStyle, 0);
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
    foodControl->SetCityProductionDialogPictureRectAndMaybeRefresh(&foodStyle, 0);
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagFood, 0x2730, 0);
  }

  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagQuer, 0x2730, 0);

  UiRuntimeSlot58();
}

void TViewMgr::UiRuntimeSlot60() {
  TView* mainView = g_pDisplayMgr->activeDialog;
  if (mainView != nullptr) {
    static_cast<TDiplomacyMapView*>(mainView)->SelectCandidateTilesWithLowGroundUnitCount();
  }
}

void TViewMgr::UiRuntimeSlot64() {
  TView* mainView = g_pDisplayMgr->activeDialog;
  if (mainView != nullptr) {
    static_cast<TDiplomacyMapView*>(mainView)->OrphanLeaf_NoCall_Ins07_004d8920();
  }
}

// FUNCTION: IMPERIALISM 0x005da360
void TViewMgr::UiRuntimeSlotBC() {
  const short activeNationId = g_pLocalizationTable->GetActiveNationId();
  if (IsNationSlotEligibleForEventProcessing(activeNationId) == 0) {
    g_pLocalizationTable->CopyScenarioNationSetupIntoFlowState(nullptr);
  }

  turn_event_ui_refresh::BindCursorPanelAndSetTurnEventCodeRange();
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTrb1);
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagDipl, 1, 0x24d9, 0x24e1);
  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagTrad, 0x100, 0x24db, 0x24e3);
  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagCity, 0x10, 0x24dd, 0x24e5);
  turn_event_ui_refresh::RefreshOrderStatusPicture(kControlTagTran, 0x1000, 0x24df, 0x24e7);

  TControl* tranControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagTran);
  if (tranControl != nullptr) {
    tranControl->AssertValid();
    g_pLocalizationTable->TestTurnFlowStatusFlagMask(0x1000);
    const short followUpPictureId =
        g_pLocalizationTable->TestTurnFlowStatusFlagMask(0x1000) ? 0x24df : 0x24e7;
    static_cast<TPicture*>(tranControl)->SetPictureResourceIdAndRefresh(followUpPictureId, true);
  }

  turn_event_ui_refresh::RefreshQuerControlLayoutAndClearText();

  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagQuer, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagCity, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagTrad, 0x2730, 0);

  if (g_pLocalizationTable->TestTurnFlowStatusFlagMask(1) == 0) {
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagDipl, 0x19, 0);
  } else {
    turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagDipl, 0x15, 0);
  }

  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagTran, 0x2730, 0);
  turn_event_ui_refresh::RefreshTaggedControlWithLocalizedString(kControlTagCity, 0x2731, 0);
}

void TViewMgr::UiRuntimeSlotC0() {}

void TViewMgr::UiRuntimeSlotC4() {}

void TViewMgr::UiRuntimeSlotC8() {}

void TViewMgr::UiRuntimeSlotCC() {}

// FUNCTION: IMPERIALISM 0x005dc1e0
void TViewMgr::UiRuntimeSlotD0() {
  turn_event_ui_refresh::RefreshToolBarClusterByTag(kControlTagTool);

  TControl* goldControl = turn_event_ui_refresh::ResolveMainTaggedControl(kControlTagGold);
  if (goldControl != nullptr) {
    goldControl->AssertValid();
    goldControl->RefreshControl();
  }

  turn_event_ui_refresh::RefreshMainCouncilTickerPanel();
}

void TViewMgr::UiRuntimeSlotD8() {}

int TViewMgr::ShowConstructionOptionsDialog() {
  return 0;
}

void TViewMgr::UiRuntimeSlotE0() {}
void TViewMgr::UiRuntimeSlotE4() {}
void TViewMgr::UiRuntimeSlotE8() {}
void TViewMgr::UiRuntimeSlotEC() {}
void TViewMgr::UiRuntimeSlotF0() {}
void TViewMgr::UiRuntimeSlotF4() {}
void TViewMgr::UiRuntimeSlotF8() {}
void TViewMgr::UiRuntimeSlotFC() {}
void TViewMgr::UiRuntimeSlot100() {}
void TViewMgr::UiRuntimeSlot104() {}
void TViewMgr::UiRuntimeSlot108() {}
void TViewMgr::UiRuntimeSlot10C() {}
void TViewMgr::UiRuntimeSlot110() {}

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
