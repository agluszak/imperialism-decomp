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

// GLOBAL: IMPERIALISM 0x0066fec4
char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

// FUNCTION: IMPERIALISM 0x00606fba
CRuntimeClass* CObject::GetRuntimeClass() {
  return &classCObject;
}

// FUNCTION: IMPERIALISM 0x00412bd0
void CObject::Serialize(CArchive*) {}

// FUNCTION: IMPERIALISM 0x00412bf0
void CObject::AssertValidOrSlot0c() {}

// FUNCTION: IMPERIALISM 0x00412c10
void CObject::DumpOrSlot10(int unused) {
  (void)unused;
}

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
