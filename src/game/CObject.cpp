#include "game/CObject.h"

#include "game/CRuntimeClass.h"

// MFC CObject RTTI was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

// MFC CRuntimeClass descriptor for CObject itself (0x6706e0), root of the m_pBaseClass
// chain. Reccmp pairs by symbol registration (the GLOBAL marker), not by value.
// GLOBAL: IMPERIALISM 0x006706e0
CRuntimeClass classCObject = {nullptr, 0, 0, nullptr, nullptr};

// The CObject vtable at 0x0066fec4 is owned by the `// VTABLE:` annotation in
// CObject.h plus real inheritance -- do NOT add a `// GLOBAL:` marker here, or reccmp
// drops the VTABLE entity as a duplicate address. This char is only a legacy stand-in
// referenced by not-yet-ported autogen vptr writes; it carries no reccmp address.
char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

// The scalar deleting destructor is compiler-generated from the virtual dtor.
// SYNTHETIC: IMPERIALISM 0x00415f00
// CObject::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00412bd0
void CObject::Serialize(CArchive*) {}

// FUNCTION: IMPERIALISM 0x00412bf0
void CObject::AssertValidOrSlot0c() {}

// FUNCTION: IMPERIALISM 0x00412c10
void CObject::DumpOrSlot10(int unused) {
  (void)unused;
}

// FUNCTION: IMPERIALISM 0x00606fba
CRuntimeClass* CObject::GetRuntimeClass() const {
  return &classCObject;
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
