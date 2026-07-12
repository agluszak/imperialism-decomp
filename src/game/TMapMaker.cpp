#include "game/TMapMaker.h"
#include "game/TObject.h"
#include "game/TControl.h"

// SYNTHETIC: IMPERIALISM 0x00525950
// TMapMaker::GetRuntimeClass
IMPLEMENT_DYNAMIC(TMapMaker, TObject)

// FUNCTION: IMPERIALISM 0x00525970
TMapMaker::TMapMaker() : TObject() {}

// SYNTHETIC: IMPERIALISM 0x00525990
// TMapMaker::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005259c0
TMapMaker::~TMapMaker() {}

// FUNCTION: IMPERIALISM 0x00526ba0
char TMapMaker::GetBoolSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00526c20
void TMapMaker::SetControlValue(int value) {}

// FUNCTION: IMPERIALISM 0x00527040
TEventHandler* TMapMaker::QueryStepValue() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00527300
void TMapMaker::DispatchQueuedUiCommandAndRelease(void* payload) {}

// FUNCTION: IMPERIALISM 0x005274d0
void TMapMaker::DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  (void)event;
}

// FUNCTION: IMPERIALISM 0x005275a0
void TMapMaker::DispatchUiSelectionToHandler(void* payload) {}

// FUNCTION: IMPERIALISM 0x00527730
void TMapMaker::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00527d00
char TMapMaker::vmethod_0023() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00527ed0
char TMapMaker::vmethod_0024() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00528140
class TView* TMapMaker::OwnerPanel() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005283c0
void TMapMaker::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x00528670
char TMapMaker::DoIdle(int action) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00528780
int TMapMaker::GetCityDialogValueDword10() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005288a0
void TMapMaker::SetCityDialogValueDword10(int value) {}

// FUNCTION: IMPERIALISM 0x00528ce0
void TMapMaker::DispatchCityProductionAction1A() {}

// FUNCTION: IMPERIALISM 0x00528e50
void TMapMaker::vmethod_0017(int param) {}

// FUNCTION: IMPERIALISM 0x005292f0
void TMapMaker::DispatchCityProductionAction1B() {}

// FUNCTION: IMPERIALISM 0x005296a0
char TMapMaker::ActivateCityProductionViewIfAllowed() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005297e0
char TMapMaker::vmethod_0080() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005298a0
int TMapMaker::GetFineGridCellBasePointerFromCoarseIndex(int coarseIndex) {
  int cell =
      (static_cast<short>(coarseIndex % 0x1b) + static_cast<short>(coarseIndex / 0x1b) * 0x6c) *
          0x90 +
      reinterpret_cast<int>(mapTileGrid08);
  if ((coarseIndex / 0x1b & 1U) != 0) {
    cell = cell + -0x48;
  }
  return cell;
}

// FUNCTION: IMPERIALISM 0x00529f60
void TMapMaker::vmethod_0025() {}

// FUNCTION: IMPERIALISM 0x0052a670
int TMapMaker::GetCityRegionIdAtTileIndex(int tileIndex) {
  if (tileIndex >= 0) {
    char* tile = mapTileGrid08 + tileIndex * 0x24;
    if (*tile == '\x05') {
      return tile[4] - 0x17;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x0052e840
void TMapMaker::vmethod_0026(int gate) {}

// FUNCTION: IMPERIALISM 0x0052e890
void TMapMaker::DispatchUiCommand19ToParent() {}

// FUNCTION: IMPERIALISM 0x0052e900
void TMapMaker::HandleCityProductionNoOp() {}
