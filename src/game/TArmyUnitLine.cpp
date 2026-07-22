#include "game/TArmyUnitLine.h"

#include "game/CString.h"
#include "game/TArmyCheckBox.h"
#include "game/TArmyUnitView.h"
#include "game/TClickZone.h"
#include "game/TGWorldButton.h"
#include "game/TMilitaryPageView.h"
#include "game/TMilitaryUnit.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004a8ca0
// TArmyUnitLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a8d10
// TArmyUnitLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyUnitLine, TLineData)

// FUNCTION: IMPERIALISM 0x004a8d30
TArmyUnitLine::TArmyUnitLine() : TLineData() {}

// SYNTHETIC: IMPERIALISM 0x004a8d60
// TArmyUnitLine::`scalar deleting destructor'
TArmyUnitLine::~TArmyUnitLine() {}

// FUNCTION: IMPERIALISM 0x004a8df0
void TArmyUnitLine::InstallViews(TView* panel, int* offsetLayout) {
  TArmyUnitView* armyView = new TArmyUnitView;
  armyView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5, 0);
  armyView->militaryUnit60 = militaryUnit10;

  int checkboxOffset[2] = {0, 0};
  int checkboxSize[2] = {0x3f, 0x31};
  TArmyCheckBox* checkbox = new TArmyCheckBox(
      armyView, checkboxOffset, checkboxSize, 4, 4,
      static_cast<TMilitaryPageView*>(panel)->primaryUnitAtlas84, militaryUnit10->orderType << 7);
  checkbox->controlTag = 0x63686563; // 'chec'
  if (militaryUnit10->GetUnitMovementClassId() != 0) {
    static_cast<TView*>(checkbox)->SetState(1, 0);
    checkbox->eventNumber60 = 4;
    if (militaryUnit10->unitOrder == 0) {
      checkbox->SetState(1, 0);
    }
  } else {
    static_cast<TView*>(checkbox)->SetState(0, 0);
    checkbox->SetState(0, 0);
  }

  CString movementHelp;
  g_pSimMgr->GetString(0x2726, militaryUnit10->GetUnitMovementClassId(), &movementHelp);
  SetControlHoverHelpText(movementHelp, checkbox);

  if (militaryUnit10->HasEraCapabilityFallbackSlot()) {
    int upgradeOffset[2] = {armyView->frameWidth34 - 0x28, 0};
    int upgradeSize[2] = {0x13, 0x12};
    TGWorldButton* upgradeButton = new TGWorldButton;
    upgradeButton->InitializeWithBitmapResource(armyView, upgradeOffset, upgradeSize, 0xdae);
    upgradeButton->SetState(1, 0);
    upgradeButton->controlTag = 0x75706772; // 'upgr'

    CString armsText;
    CString cashText;
    CString fuelText;
    CString templateText;
    CString hoverText;
    short candidateSlot;
    short armsCost;
    short cashCost;
    short fuelCost;
    militaryUnit10->GetEraCapabilityFallbackCosts(&candidateSlot, &armsCost, &cashCost, &fuelCost);
    armsText.Format(g_szDecimalFormat, static_cast<int>(armsCost));
    g_pSimMgr->NumToCurrency(cashCost, &cashText);
    if (fuelCost == 0) {
      g_pSimMgr->GetString(0x2746, 2, &templateText);
      scanBracketExpressions(g_pSimMgr, &hoverText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(armsText), static_cast<LPCSTR>(cashText));
    } else {
      fuelText.Format(g_szDecimalFormat, static_cast<int>(fuelCost));
      g_pSimMgr->GetString(0x2746, 6, &templateText);
      scanBracketExpressions(g_pSimMgr, &hoverText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(armsText), static_cast<LPCSTR>(fuelText),
                             static_cast<LPCSTR>(cashText));
    }
    SetControlHoverHelpText(hoverText, upgradeButton);
  }

  int nameOffset[2] = {0x40, 0};
  int nameSize[2] = {0x80, 0x18};
  TClickZone* nameZone = new TClickZone;
  nameZone->InitializeUiResourceEntryFrameAndParent(0, armyView, nameOffset, nameSize, 4, 4, 0);
  nameZone->controlTag = 0x6e616d65; // 'name'
  CString nameHelp;
  g_pSimMgr->GetString(0x2746, 1, &nameHelp);
  SetControlHoverHelpText(nameHelp, nameZone);
}
