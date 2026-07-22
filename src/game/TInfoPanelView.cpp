#include "game/TInfoPanelView.h"

#include "game/TControl.h"
#include "game/TCluster.h"
#include "game/TDiplomacyMapView.h"
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
void TInfoPanelView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
  diplomacyMapView60 = static_cast<TDiplomacyMapView*>(ownerContext);

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
void TInfoPanelView::Draw(RECT* rectBuffer) {
  // TODO: paint the info panel for `rectBuffer` (0x004fa190).  This is a large
  // draw routine that builds a row of text strings via g_pSimMgr->GetString and
  // applies them to the child controls, then clears `this` caption.  Ported
  // prerequisites: the TInfoPanelView/TDiplomacyMapView fields and text helpers.
}

// FUNCTION: IMPERIALISM 0x004facc0
void TInfoPanelView::Setup() {
  TCluster* overlayCluster = static_cast<TCluster*>(ResolveControlByTag(0x636c7573)); // 'clus'
  overlayCluster->AssertValid();
  SetControlHoverHelpText(CString(g_pDiplomacyPanelEmptyText_00654ec8), overlayCluster);
  overlayCluster->SetSelectedChildTagAndRefresh(0x6f767230); // 'ovr0'

  diplomacyMapView60->actionCodeBC = 0xd;
  selectedOverlayMode6C = 0;

  TControl* mapKey = static_cast<TControl*>(ResolveControlByTag(0x6d6b6579)); // 'mkey'
  mapKey->AssertValid();
  mapKey->SetDiplomacyNationSelectionFilterAndRefreshRows(0);
}

// FUNCTION: IMPERIALISM 0x004fad60
void TInfoPanelView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xc) {
    short selectedOverlayMode = (short)sourceHandler->controlTag - 0x7230;
    diplomacyMapView60->interactionModeAt94 = selectedOverlayMode;
    InvalidateCityDialogRectRegion(&diplomacyMapView60->mapViewportRect514, 1);
    selectedOverlayMode6C = selectedOverlayMode;
    TControl* mkey = static_cast<TControl*>(ResolveControlByTag(0x6d6b6579));
    mkey->AssertValid();
    mkey->SetDiplomacyNationSelectionFilterAndRefreshRows(selectedOverlayMode);
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004fae00
void TInfoPanelView::SetInfoCountry(short countryId) {
  // Initialize the 8-byte/4-short field array to -1.
  *(reinterpret_cast<int*>(&countryInfoCategoryIndices64[0])) = -1;
  *(reinterpret_cast<int*>(&countryInfoCategoryIndices64[2])) = -1;

  if (countryId < 7) {
    // Great-power row: scan 0x898 + 2*countryId + i*0xa0 for i=0..3 and store
    // the first four non-zero values as 13, 14, 15, 16.
    short* base = reinterpret_cast<short*>(
        reinterpret_cast<char*>(g_pNationInteractionStateManager) + 0x898 + countryId * 2);
    int count = 0;
    for (int i = 0; i < 4; i++) {
      if (base[i * 80] != 0) {
        countryInfoCategoryIndices64[count++] = (short)(13 + i);
      }
    }
  } else {
    // Minor-power row: bubble-sort the first 7 values from
    // secondary->diplomacySaveExt13c[0..6], then copy the first 4 positive
    // indices into countryInfoCategoryIndices64.
    TMinor* secondary = g_apSecondaryNationStateSlots[countryId];
    short values[7];
    short indices[7];
    for (int idx = 0; idx < 7; idx++) {
      values[idx] = secondary->diplomacySaveExt13c[idx];
      if (idx == 6 &&
          g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] ==
              0) {
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
        countryInfoCategoryIndices64[copyIdx] = indices[copyIdx];
      }
    }
  }
}
