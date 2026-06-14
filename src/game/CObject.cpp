#include "game/CObject.h"

#include "game/CRuntimeClass.h"

// MFC CObject RTTI was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// MFC CRuntimeClass descriptor for CObject itself (0x6706e0), root of the m_pBaseClass
// chain. Reccmp pairs by symbol registration (the GLOBAL marker), not by value.
// GLOBAL: IMPERIALISM 0x006706e0
CRuntimeClass classCObject = {0};

CObject::~CObject() {}

// FUNCTION: IMPERIALISM 0x00606fba
CRuntimeClass* CObject::GetRuntimeClass() {
  return &classCObject;
}
void CObject::Serialize(CArchive*) {}
int CObject::AssertValidOrSlot0c() {
  return 0;
}
void CObject::DumpOrSlot10() {}

// FUNCTION: IMPERIALISM 0x00606fc0
int CObject::IsKindOf(const CRuntimeClass* pClass) {
  CRuntimeClass* pRuntimeClass = GetRuntimeClass();
  return pRuntimeClass->IsDerivedFrom(pClass);
}

// FUNCTION: IMPERIALISM 0x00606fd2
CObject* AfxDynamicDownCast(CRuntimeClass* pClass, CObject* pObject) {
  if (pObject != 0 && pObject->IsKindOf(pClass) != 0) {
    return pObject;
  }
  return 0;
}
