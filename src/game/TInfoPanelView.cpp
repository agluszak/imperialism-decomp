#include "game/TInfoPanelView.h"

#include "game/TControl.h"
#include "game/TMinor.h"
#include "game/TSimMgr.h"
#include "game/TTradeMgr.h"
#include "game/TTechMgr.h"
#include "game/global_data_tables.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004304d0
// TInfoPanelView::`scalar deleting destructor'
TInfoPanelView::~TInfoPanelView() {}
// SYNTHETIC: IMPERIALISM 0x004f9f60
// TInfoPanelView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004f9ff0
// TInfoPanelView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TInfoPanelView, TPanelView)

TInfoPanelView::TInfoPanelView() {}

// FUNCTION: IMPERIALISM 0x004fa010
void TInfoPanelView::NoOpUiLifecycleHook(int arg) {
  TView::NoOpUiLifecycleHook(arg);
  m_panelData = ownerContext;

  // Resource tag array for the four "ovr*" nation labels (ovr0/ovr4/ovr1/ovr2)
  // as laid out by the original instruction sequence.
  const short kOvrTagOffsets[4] = {0, 4, 1, 2};
  for (int i = 0; i < 4; i++) {
    TView* child = ResolveControlByTag(0x6f767230 + kOvrTagOffsets[i]);
    child->AssertValid();
    CString text;
    g_pSimMgr->GetString(0x2733, (short)(0x4e + i), &text);
    SetControlHoverHelpText(text, child);
  }

  CString empty(g_szEmptyString);
  SetControlHoverHelpText(empty, this);
}

// FUNCTION: IMPERIALISM 0x004fa190
void TInfoPanelView::ApplyRectSlot110(RECT* rectBuffer) {
  // TODO: paint the info panel for `rectBuffer` (0x004fa190).  This is a large
  // draw routine that builds a row of text strings via g_pSimMgr->GetString and
  // applies them to the child controls, then clears `this` caption.  Ported
  // prerequisites: the TInfoPanelView/TInfoPanelData fields and text helpers.
}

// FUNCTION: IMPERIALISM 0x004facc0
undefined TInfoPanelView::OrphanRetStub_00430550() {
  // TODO: resolves the 'clus' child, applies the empty string, calls an
  // unidentified +0x1c8 vtable slot with a pushed 0x6f767230 arg, and then
  // resets the panel state and mkey selection.  The slot semantics (TCluster
  // thunk_GetCityDialogValueDwordC -> TEventHandler::GetCityDialogValueDwordC)
  // do not consume the pushed argument, so the exact call target is unresolved
  // and remains stubbed while the surrounding TInfoPanelView slots are ported.
  return 0;
}

struct TInfoPanelData {
  unsigned char padding_0x00[0x94];
  int selectedNation; // 0x94
  short field_0x98;   // 0x98
  unsigned char padding_0x9a[0x47a];
  RECT region; // 0x514
};

// FUNCTION: IMPERIALISM 0x004fad60
void TInfoPanelView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    TInfoPanelData* data = static_cast<TInfoPanelData*>(m_panelData);
    short selectedNationShort = (short)sourceHandler->controlTag - 0x7230;
    int selectedNation = selectedNationShort;
    data->selectedNation = selectedNation;
    InvalidateCityDialogRectRegion(&data->region, 1);
    m_selectedNation = selectedNation;
    TControl* mkey = static_cast<TControl*>(ResolveControlByTag(0x6d6b6579));
    mkey->AssertValid();
    mkey->SetDiplomacyNationSelectionFilterAndRefreshRows(selectedNationShort);
  }
  TEventHandler::HandleEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004fae00
undefined TInfoPanelView::OrphanLeaf_NoCall_Ins97_004fae00(short param_1) {
  // Initialize the 8-byte/4-short field array to -1.
  *(reinterpret_cast<int*>(&field_0x64[0])) = -1;
  *(reinterpret_cast<int*>(&field_0x64[2])) = -1;

  if (param_1 < 7) {
    // Great-power row: scan 0x898 + 2*param_1 + i*0xa0 for i=0..3 and store
    // the first four non-zero values as 13, 14, 15, 16 in field_0x64.
    short* base = reinterpret_cast<short*>(
        reinterpret_cast<char*>(g_pNationInteractionStateManager) + 0x898 + param_1 * 2);
    int count = 0;
    for (int i = 0; i < 4; i++) {
      if (base[i * 80] != 0) {
        field_0x64[count++] = (short)(13 + i);
      }
    }
  } else {
    // Minor-power row: bubble-sort the first 7 values from
    // secondary->diplomacySaveExt13c[0..6], then copy the first 4 positive
    // indices into field_0x64.
    TMinor* secondary = g_apSecondaryNationStateSlots[param_1];
    short values[7];
    short indices[7];
    for (int idx = 0; idx < 7; idx++) {
      values[idx] = secondary->diplomacySaveExt13c[idx];
      if (idx == 6 && g_pCityOrderCapabilityState->hasProductionOrder193 == 0) {
        values[6] = 0;
      }
      indices[idx] = (short)idx;
    }

    // Selection sort descending by values.
    for (int outer = 0; outer < 6; outer++) {
      for (int inner = outer; inner < 7; inner++) {
        if (values[inner] > values[outer]) {
          short temp = values[outer];
          values[outer] = values[inner];
          values[inner] = temp;
          short tempIdx = indices[outer];
          indices[outer] = indices[inner];
          indices[inner] = tempIdx;
        }
      }
    }

    for (int copyIdx = 0; copyIdx < 4; copyIdx++) {
      if (values[copyIdx] > 0) {
        field_0x64[copyIdx] = indices[copyIdx];
      }
    }
  }

  return 0;
}
