#include "game/TNavyTacUnit.h"

#include "game/TTaskForce.h"

// FUNCTION: IMPERIALISM 0x0059ed60
TTaskForce* TNavyTacUnit::GetSourceTaskForce() {
  return sourceTaskForce34;
}

// SYNTHETIC: IMPERIALISM 0x0059ed80
// TNavyTacUnit::`scalar deleting destructor'
TNavyTacUnit::~TNavyTacUnit() {}
// SYNTHETIC: IMPERIALISM 0x005a6240
// TNavyTacUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a6270
// TNavyTacUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyTacUnit, TTacticalUnit)

TNavyTacUnit::TNavyTacUnit() {}

// FUNCTION: IMPERIALISM 0x005a6310
int TNavyTacUnit::GetBaseActionPoints() {
  return baseActionPoints3c;
}

// FUNCTION: IMPERIALISM 0x005a6330
int TNavyTacUnit::GetUnitRange() {
  return sourceTaskForce34->GetOrderNodeDescriptorWord0CByResourceType();
}

// FUNCTION: IMPERIALISM 0x005a6350
undefined TNavyTacUnit::OrphanLeaf_NoCall_Ins02_005a5d80() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a6370
undefined TNavyTacUnit::OrphanLeaf_NoCall_Ins02_005a5da0() {
  return 0;
}
