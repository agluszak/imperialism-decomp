#include "game/TInfoPanelView.h"

#include "game/TControl.h"

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
}

// FUNCTION: IMPERIALISM 0x004fa190
void TInfoPanelView::ApplyRectSlot110(RECT* rectBuffer) {
}

// FUNCTION: IMPERIALISM 0x004facc0
undefined TInfoPanelView::OrphanRetStub_00430550() {
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
  return 0;
}
