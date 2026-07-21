#include "game/TShipBuildingTask.h"
// SYNTHETIC: IMPERIALISM 0x005ae650
// TShipBuildingTask::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ae680
// TShipBuildingTask::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipBuildingTask, TCityTask)

// FUNCTION: IMPERIALISM 0x005ae6a0
TShipBuildingTask::TShipBuildingTask() : TCityTask() {}

// SYNTHETIC: IMPERIALISM 0x005ae6c0
// TShipBuildingTask::`scalar deleting destructor'
TShipBuildingTask::~TShipBuildingTask() {}

// FUNCTION: IMPERIALISM 0x005ae780
bool TShipBuildingTask::Tick(TSortedList*) {
  return false;
}

// FUNCTION: IMPERIALISM 0x005ae9e0
void TShipBuildingTask::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x005aea70
void TShipBuildingTask::ReadFrom(TStream* stream) {}
