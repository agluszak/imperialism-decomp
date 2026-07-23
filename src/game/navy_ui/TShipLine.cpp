#include "game/navy_ui/TShipLine.h"
#include "game/ui_tags_common.h"

#include "game/ui_screens/CString.h"
#include "game/military_ui/TArmyCheckBox.h"
#include "game/ui_screens/TClickZone.h"
#include "game/navy/TMapOrderChildLinkNode.h"
#include "game/navy/TMilitaryPageView.h"
#include "game/navy/TShip.h"
#include "game/navy_ui/TShipView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00564f90
// TShipLine::`scalar deleting destructor'
TShipLine::~TShipLine() {}
// SYNTHETIC: IMPERIALISM 0x00565030
// TShipLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005650a0
// TShipLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipLine, TLineData)

TShipLine::TShipLine() {}

// FUNCTION: IMPERIALISM 0x00565100
void TShipLine::InstallViews(TView* panel, int* offsetLayout) {
  TShipView* shipView = new TShipView();
  shipView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &field08, 5, 5, 0);
  shipView->shipNode60 = shipNode10;
  shipView->field64 = taskForce18;

  int checkboxOffset[2] = {0, 0};
  int checkboxSize[2] = {0x50, 0x2d};
  int atlasOffset = g_ShipRosterAtlasHorizontalOffsetByResourceType_006985E8[shipNode10->type];
  TArmyCheckBox* checkbox =
      new TArmyCheckBox(shipView, checkboxOffset, checkboxSize, 5, 5,
                        static_cast<TMilitaryPageView*>(panel)->primaryUnitAtlas84, atlasOffset);
  checkbox->controlTag = kControlTagChec; // 'chec'
  checkbox->eventNumber60 = 4;
  checkbox->SetState(childLink14->active, 0);

  int nameOffset[2] = {0x40, 0};
  int nameSize[2] = {0x80, 0x18};
  TClickZone* nameZone = new TClickZone();
  nameZone->InitializeUiResourceEntryFrameAndParent(0, shipView, nameOffset, nameSize, 4, 4, 0);
  nameZone->controlTag = kControlTagName; // 'name'

  CString nameHelp;
  g_pSimMgr->GetString(0x2746, 4, &nameHelp);
  SetControlHoverHelpText(nameHelp, nameZone);
}
