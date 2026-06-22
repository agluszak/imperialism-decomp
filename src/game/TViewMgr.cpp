#include "game/TViewMgr.h"

// TSimMgr global instance @ 0x6a20f8 (a.k.a. g_pLocalizationTable / turn-state
// manager). Forward-declared here to avoid pulling the full TSimMgr header.
class TSimMgr;
extern "C" TSimMgr* g_pLocalizationTable;

// Free-function thunks reached through the ILT jump table; declared in the generic
// repo form and invoked through typed __cdecl casts at the callsites.
undefined4 LoadTurnEventCursorByResourceIdOffset1000(void);
undefined4 MapTurnEventCodeToPaletteIndex(void);
undefined4 SetQuickDrawFillColorFromPaletteIndex(void);
undefined4 UpdatePaletteIndexWithDefaultFallback(void);

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
  // TODO(batch2): port raw-vtable refresh-gold-dialog body via real receiver virtuals.
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
void TViewMgr::ComputeTurnEventDialogPlacementByCode() {
  // TODO(batch2): port dialog placement (struct-return-via-hidden-ptr + raw vtable).
}

// FUNCTION: IMPERIALISM 0x005d6b70
void TViewMgr::RefreshMainViewNationIndicatorForCurrentTurnEvent() {
  // TODO(batch2): port main-view nation indicator refresh via real receiver virtuals.
}

// FUNCTION: IMPERIALISM 0x005dcaa0
void TViewMgr::HandleTurnEventVtableSlot2CInitializeHotKeyDialog() {
  // TODO(batch2): port hotkey-dialog init (CDialog + SEH + raw vtable).
}
