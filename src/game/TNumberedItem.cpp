#include "game/TNumberedItem.h"

// FUNCTION: IMPERIALISM 0x005077a0
CRuntimeClass* TNumberedItem::GetRuntimeClass() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x00507800
// TNumberedItem::`scalar deleting destructor'
TNumberedItem::~TNumberedItem() {}

// FUNCTION: IMPERIALISM 0x005078a0
void TNumberedItem::ApplyRectSlot110(RECT* rectBuffer) {
}

// Slot 0x1cc body lives at 0x00572bb0, which is owned by TNoHilitePicture
// (the function sits in TNoHilitePicture's address range, right after its dtor
// at 0x572b60). TNumberedItem shares the same slot in the binary but cannot own
// the address; this unmarked stub keeps its own vtable slot compilable.
undefined TNumberedItem::UniversityDialogMethod_00405623() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00573430
undefined TNumberedItem::LoadPictureResourceRegionAndRefresh() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00573650
void TNumberedItem::Free() {
}

// FUNCTION: IMPERIALISM 0x00573690
undefined TNumberedItem::OrphanCallChain_C1_I08_00573690(undefined2 param_1, char param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005736c0
undefined TNumberedItem::OrphanCallChain_C1_I14_005736c0(ushort param_1, char param_2, char param_3) {
  return 0;
}

int TNumberedItem::QuerySelectedIndexSlotBC() { return 0; }

undefined TNumberedItem::AssertCityProductionGlobalStateInitialized() { return 0; }

bool TNumberedItem::LogUnhandledDialogMethodAndReturnFalse() { return 0; }

void TNumberedItem::BeginMouseCaptureAndStartRepeatTimer(CPoint * point) {}

void TNumberedItem::SetControlPictureEntryAndMaybeRefresh(int * pPictureEntryRef, bool fRefreshNow) {}

undefined TNumberedItem::SetCityProductionDialogPictureRectAndMaybeRefresh() { return 0; }

void TNumberedItem::SetControlStateFlagAndMaybeRefresh(bool fEnabledState, bool fRefreshNow) {}

void TNumberedItem::DispatchPictureResourceCommand(int nEventType, void * pEventSender, void * pEventDataA, void * pEventDataB) {}

undefined TNumberedItem::VTableSlot5B() { return 0; }

undefined TNumberedItem::DeserializeCityProductionQueueCommand(TTEView * param_1) { return 0; }

undefined TNumberedItem::NoOpUiViewSlotHandler() { return 0; }

undefined TNumberedItem::OrphanRetStub_00487a00() { return 0; }

void TNumberedItem::ResetPictureResourceEntry() {}

TObject* TNumberedItem::ShallowClone() { return 0; }
