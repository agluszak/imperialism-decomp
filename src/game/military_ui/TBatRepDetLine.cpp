#include "game/military_ui/TBatRepDetLine.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/military_ui/TArmyBoyView.h"
#include "game/military_ui/TArmyCheckBox.h"
#include "game/military_ui/TBattleUnitsView.h"
#include "game/military_ui/TInterruptusView.h"
#include "game/military_ui/TItemBoyView.h"
#include "game/military_ui/TMerchantBoyView.h"
#include "game/military_ui/TNavyBoyView.h"

// SYNTHETIC: IMPERIALISM 0x004affd0
// TBatRepDetLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004b0000
TBatRepDetLine::~TBatRepDetLine() {}
// SYNTHETIC: IMPERIALISM 0x004aff60
// TBatRepDetLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x004b0020
// TBatRepDetLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TBatRepDetLine, TLineData)

TBatRepDetLine::TBatRepDetLine() {}

// FUNCTION: IMPERIALISM 0x004b0040
void TBatRepDetLine::InstallViews(TView* panel, int* offsetLayout) {
  panel->AssertValid();
  TBattleUnitsView* battleUnitsView = static_cast<TBattleUnitsView*>(panel);

  switch (battleDetail14->categoryTag28) {
  case kControlTagArmy: { // 'army'
    TArmyBoyView* armyView = new TArmyBoyView;
    armyView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5, 0);
    armyView->battleDetail60 = battleDetail14;

    int checkboxOffset[2] = {0, 0};
    int checkboxSize[2] = {0x40, 0x31};
    TArmyCheckBox* checkbox = new TArmyCheckBox(armyView, checkboxOffset, checkboxSize, 5, 5,
                                                battleUnitsView->primaryUnitAtlas84,
                                                battleDetail14->payload.army.unitType00 << 7);
    static_cast<TView*>(checkbox)->SetState(0, 0);
    checkbox->SetState(1, 0);
    break;
  }
  case kControlTagItem: { // 'item'
    TItemBoyView* itemView = new TItemBoyView;
    itemView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5, 0);
    itemView->battleDetail60 = battleDetail14;
    break;
  }
  case kControlTagRupt: { // 'rupt'
    TInterruptusView* interruptView = new TInterruptusView;
    interruptView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5,
                                                           0);
    interruptView->battleDetail60 = battleDetail14;
    break;
  }
  case kControlTagNavy: { // 'navy'
    TNavyBoyView* navyView = new TNavyBoyView;
    navyView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5, 0);
    navyView->battleDetail60 = battleDetail14;

    short shipAtlasOffsets[14] = {0,     0,     0,     0, 0xa0,  0,     0,
                                  0x140, 0x1e0, 0x280, 0, 0x320, 0x3c0, 0x460};
    int checkboxOffset[2] = {0, 0};
    int checkboxSize[2] = {0x50, 0x2d};
    TArmyCheckBox* checkbox = new TArmyCheckBox(
        navyView, checkboxOffset, checkboxSize, 5, 5, battleUnitsView->secondaryUnitAtlas88,
        shipAtlasOffsets[battleDetail14->payload.navy.shipType00]);
    static_cast<TView*>(checkbox)->SetState(0, 0);
    checkbox->SetState(1, 0);
    break;
  }
  case kControlTagMerc: { // 'merc'
    TMerchantBoyView* merchantView = new TMerchantBoyView;
    merchantView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5,
                                                          0);
    merchantView->battleDetail60 = battleDetail14;

    short merchantAtlasSlots[14] = {0, 0, 1, 0, 0, 2, 3, 0, 0, 0, 4, 0, 0, 0};
    int checkboxOffset[2] = {0, 0};
    int checkboxSize[2] = {0x50, 0x2d};
    int atlasOffset = merchantAtlasSlots[battleDetail14->payload.merchant.commodityType00] * 0x50;
    TArmyCheckBox* checkbox = new TArmyCheckBox(merchantView, checkboxOffset, checkboxSize, 5, 5,
                                                battleUnitsView->primaryUnitAtlas84, atlasOffset);
    static_cast<TView*>(checkbox)->SetState(0, 0);
    checkbox->SetState(0, 0);
    break;
  }
  }
}
