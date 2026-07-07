#include "game/TRadioTextCluster.h"
// SYNTHETIC: IMPERIALISM 0x005795b0
// TRadioTextCluster::CreateObject

// SYNTHETIC: IMPERIALISM 0x00579680
// TRadioTextCluster::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRadioTextCluster, TCluster)

// FUNCTION: IMPERIALISM 0x005796a0
TRadioTextCluster::TRadioTextCluster() : TCluster() {
  word8C = 0x4b;
  word8E = 0x49;
  selectedOption90 = -1;
  word92 = 0;
  word94 = 2;
}

// SYNTHETIC: IMPERIALISM 0x005796f0
// TRadioTextCluster::`scalar deleting destructor'
TRadioTextCluster::~TRadioTextCluster() {}

// FUNCTION: IMPERIALISM 0x00579740
void TRadioTextCluster::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x00579770
void TRadioTextCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00579a60
void TRadioTextCluster::ApplyRectSlot110(RECT* rectBuffer) {}
