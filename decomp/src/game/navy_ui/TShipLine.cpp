#include "game/navy_ui/TShipLine.h"
#include "game/ui_tags_common.h"

#include "game/core/CString.h"
#include "game/military_ui/TArmyCheckBox.h"
#include "game/ui_screens/TClickZone.h"
#include "game/navy/TMapOrderChildLinkNode.h"
#include "game/navy/TMilitaryPageView.h"
#include "game/navy/TShip.h"
#include "game/navy_ui/TShipView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TShipLine, TLineData)

// FUNCTION: IMPERIALISM 0x005650c0
void TShipLine::IShipLine(short rowArg, short colArg, int* bounds,
                          TMapOrderChildLinkNode* childLink, TTaskForce* force) {
  ILineData(rowArg, colArg, bounds);
  this->childLink = childLink;
  TShip* ship = childLink->payload;
  taskForce = force;
  shipNode = ship;
}

// FUNCTION: IMPERIALISM 0x00565100
void TShipLine::InstallViews(TView* panel, int* offsetLayout) {
  TShipView* shipView = new TShipView();
  shipView->InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, &layoutWidth, 5, 5, 0);
  shipView->shipNode = shipNode;
  shipView->taskForce = taskForce;

  int checkboxOffset[2] = {0, 0};
  int checkboxSize[2] = {0x50, 0x2d};
  int atlasOffset = g_ShipRosterAtlasHorizontalOffsetByResourceType[shipNode->type];
  TArmyCheckBox* checkbox =
      new TArmyCheckBox(shipView, checkboxOffset, checkboxSize, 5, 5,
                        static_cast<TMilitaryPageView*>(panel)->primaryUnitAtlas, atlasOffset);
  checkbox->controlTag = kControlTagChec; // 'chec'
  checkbox->eventNumber = 4;
  checkbox->SetState(childLink->active, static_cast<unsigned char>(0));

  int nameOffset[2] = {0x40, 0};
  int nameSize[2] = {0x80, 0x18};
  TClickZone* nameZone = new TClickZone();
  nameZone->InitializeUiResourceEntryFrameAndParent(0, shipView, nameOffset, nameSize, 4, 4, 0);
  nameZone->controlTag = kControlTagName; // 'name'

  CString nameHelp;
  g_pSimMgr->GetString(0x2746, 4, &nameHelp);
  SetControlHoverHelpText(nameHelp, nameZone);
}
