#include "game/military_ui/TMiniArmyLine.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/CString.h"
#include "game/ui_screens/TGWorldButton.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_ui/TMiniArmyView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/military_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004aa840
// TMiniArmyLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004aa870
TMiniArmyLine::~TMiniArmyLine() {}
// SYNTHETIC: IMPERIALISM 0x004aa890
// TMiniArmyLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x004aa900
// TMiniArmyLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniArmyLine, TLineData)

// FUNCTION: IMPERIALISM 0x004aa960
void TMiniArmyLine::InstallViews(TView* panel, int* offsetLayout) {
  TMiniArmyView* armyView = new TMiniArmyView;
  armyView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5, 0);
  armyView->militaryUnit84 = militaryUnit10;
  armyView->eventNumber60 = 0x22;
  SetControlHoverHelpText(CString(g_pMiniCivSharedText_0064cb18), armyView);

  if (militaryUnit10->CanUpgrade()) {
    int upgradeOffset[2] = {0x73, 0};
    int upgradeSize[2] = {0x13, 0x12};
    TGWorldButton* upgradeButton = new TGWorldButton;
    upgradeButton->InitializeWithBitmapResource(armyView, upgradeOffset, upgradeSize, 0xdae);
    upgradeButton->SetState(1, 0);
    upgradeButton->controlTag = kControlTagUpgr; // 'upgr'

    CString armsText;
    CString cashText;
    CString fuelText;
    CString templateText;
    CString hoverText;
    short candidateSlot;
    short armsCost;
    short cashCost;
    short fuelCost;
    militaryUnit10->UpgradeRequirements(candidateSlot, armsCost, cashCost, fuelCost);
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
}
