#include "game/CObject.h"

// The CObject vtable at 0x0066fec4 is owned by the `// VTABLE:` annotation in
// CObject.h plus real inheritance -- do NOT add a `// GLOBAL:` marker here, or reccmp
// drops the VTABLE entity as a duplicate address. This char is only a legacy stand-in
// referenced by not-yet-ported autogen vptr writes; it carries no reccmp address.
char PTR_GetCObjectRuntimeClass_RuntimeObjectBaseState_0066FEC4;

// The scalar deleting destructor is compiler-generated from the virtual dtor.
// SYNTHETIC: IMPERIALISM 0x00415f00
// CObject::`scalar deleting destructor'

// LIBRARY: IMPERIALISM 0x00412bd0
// CObject::Serialize

// LIBRARY: IMPERIALISM 0x00412bf0
// CObject::AssertValid

// LIBRARY: IMPERIALISM 0x00412c10
// CObject::Dump

// LIBRARY: IMPERIALISM 0x00606fba
// CObject::GetRuntimeClass

// LIBRARY: IMPERIALISM 0x00606fc0
// CObject::IsKindOf

// LIBRARY: IMPERIALISM 0x00606fd2
// AfxDynamicDownCast
