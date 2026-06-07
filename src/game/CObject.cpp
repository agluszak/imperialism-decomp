#include "game/CObject.h"

CObject::~CObject() {}

void* CObject::GetRuntimeClass() {
  return 0;
}
void CObject::Serialize(CArchive*) {}
int CObject::AssertValidOrSlot0c() {
  return 0;
}
void CObject::DumpOrSlot10() {}
